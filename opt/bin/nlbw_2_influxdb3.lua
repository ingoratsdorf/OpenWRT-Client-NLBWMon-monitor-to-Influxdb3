#!/usr/bin/env lua

-- --------------------------------------------------------------------------------
-- CONFIGURATION

-- **Cache file path: pick a temp file name**
local cache_file_path = "/tmp/nlbw_2_influxdb3.maclist.json"
-- **User mac to host name mapping file**
local user_list_path = "./nlbw_2_influxdb3.maclist.txt"
-- this is the local domain that will be removed from any nslookup hostnames
local remove_local_domain = ".ratsdorf.home.arpa"

-- **InfluxDB Configuration**
local influxdb_url = "http://192.168.100.38:8181/api/v3/write_lp?db=nlbwmon&precision=second"
local influxdb_token = "apiv3_W0mOFeIa-4Uvnpi2VueHap7m1mect2CaOqzsD-e5UL4tX_vFKOntgAjmIIm4QrHNC78F__7gmSy9vL6KsiI0rA"


-- -----------------------------------------------------------------------------


-- **nlbwmon to InfluxDB2 Lua Script**
local socket = require("socket")  -- Requires luasocket, opkg install luasocket
local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("cjson")  -- Requires cjson, opkg install lua-cjson


-- Load hostname cache
--- Loads cache from user specified file.
---
--- Purpose:
--- Read and restore the cache used by the monitor from JSON string in user specified file.
---
--- Returns:
--- @return array of tuples, essentially [mac_address, hostname]
local function load_cache()
  local cache = {}
  local f = io.open(cache_file_path, "r")
  if f then
    local content = f:read("*a")
    f:close()
    cache = json.decode(content) or {}
  end
  return cache
end

-- Save hostname cache
--- Saves cache to user specified file.
---
--- Purpose:
--- Saves cache to user specified file as a json string
---
--- Returns:
--- @return array of tuples, essentially [mac_address, hostname]
local function save_cache(cache)
  local f = io.open(cache_file_path, "w")
  if f then
    f:write(json.encode(cache))
    f:close()
  end
end

--[[
Load and normalize lease information from system lease sources.
This function collects associations between MAC addresses, IP addresses and hostnames
by parsing available DHCP lease files, hostapd/iw station lists and ARP/neighbor caches.
It returns structured, normalized data suitable for use by the exporter.

Returns:
  leases (table) - array of lease entry tables in discovery order. Each entry contains:

    .mac       (string)   - normalized MAC address (lowercase, colon-separated)
    .ip        (string)   - IP address (IPv4 or IPv6) from the lease/source
    .hostname  (string|nil)- hostname associated with the lease, if available
    .source    (string)   - source identifier (e.g. "dnsmasq", "udhcpd", "hostapd", "arp")
    .ts        (number|nil)- timestamp (epoch) if the source provides one

  by_mac (table) - map: normalized_mac -> lease entry (most recent/authoritative for that MAC)
  by_ip  (table) - map: ip -> lease entry (most recent/authoritative for that IP)

Behavior and guarantees:
  - MAC addresses are normalized to a consistent lowercase, colon-separated format.
  - When multiple sources provide conflicting information, a deterministic precedence is used
    (typically DHCP lease files preferred over ARP/neighbor influxdb_entries); the function ensures
    one canonical entry per MAC/IP in the by_mac/by_ip maps.
  - Missing or unreadable sources are tolerated: the function skips them and continues parsing
    other available sources.
  - Parsing errors for a particular source do not cause a global failure; invalid influxdb_entries are ignored.

]]
local function load_leases()
  local leases = {}
  local lease_file = io.open("/tmp/dhcp.leases", "r")
  if lease_file then
    for line in lease_file:lines() do
      local ts, mac, ip, name = line:match("^(%d+)%s+(%S+)%s+(%S+)%s+(%S+)")
      if ip and name and name ~= "*" then
        leases[ip] = name
      end
    end
    lease_file:close()
  end
  return leases
end

-- try the owrt_client_discovery.maclist.txt file for custom hostnames
-- this file should contain lines like:
-- 00:11:22:33:44:55 mydevice
-- where the first part is the MAC address and the second part is the hostname
-- this allows users to define custom names for devices that may not have a hostname
-- or to override the default hostname resolution
-- the file should be placed in the same directory as this script
-- and should be readable by the user running this script
local function load_hosts()
  local hosts = {}
  local host_file = io.open(user_list_path, "r")
  if host_file then
    for line in host_file:lines() do
      local mac, name = line:match("^(%S+)%s+(%S+)")
      if mac and name then
        hosts[string.lower(mac)] = name
      end
    end
    host_file:close()
  end
  return hosts
end


-- **Format Data for InfluxDB**
local function format_influxdb_line_protocol(mac,ip,hostname,conns,rx_bytes,rx_packets,tx_bytes,tx_packets, timestamp)
    -- Line protocol format: measurement,tag=value field=value timestamp
    return string.format(
        "nlbwmon_traffic,mac=%s,ip=%s,hostname=%s conns=%.0fu,rx_bytes=%.0fu,rx_packets=%.0fu,tx_bytes=%.0fu,tx_packets=%.0fu %.0f",
        mac, ip, hostname, conns, rx_bytes, rx_packets, tx_bytes, tx_packets, timestamp
    )
end

-- **Send Data to InfluxDB**
local function send_to_influxdb(payload)
    local response_body = {}
    local res, code, headers, status = http.request{
        url = influxdb_url,
        method = "POST",
        headers = {
            ["Authorization"] = "Bearer " .. influxdb_token,
            ["Content-Type"] = "text/plain",
            ["Content-Length"] = tostring(#payload)
        },
        source = ltn12.source.string(payload),
        sink = ltn12.sink.table(response_body)
    }

    if code == 204 then
        print("Data successfully sent to InfluxDB.")
    else
        print("Failed to send data to InfluxDB. HTTP Code: " .. tostring(code))
        print("Response: " .. table.concat(response_body))
    end
end

-- load local cache
local hostname_cache = load_cache()
-- Load DHCP leases into a lookup table
local leases = load_leases()
-- Load user-defined host mappings
local hosts = load_hosts()
-- current timestamp
local timestamp = os.time()



-- Run the nlbw command and capture output
-- This returns lines like in a json structure with fields:
-- {"columns":["family","mac","ip","conns","rx_bytes","rx_pkts","tx_bytes","tx_pkts"],"data":[[ .. ]]}
local handle = io.popen("sudo nlbw -c json -n -g mac,ip,fam -q")
local output = handle:read("*a")
handle:close()

-- Split output into lines and filter non-usable lines out
local lines = json.decode(output).data or [[]]

-- This will hold all influxdb entries to be written
local influxdb_entries = {}

-- Process each line (skip header)
for i = 1, #lines do
  local line = lines[i]
  local mac = string.lower(line[2]) or ""
  local ip = line[3] or ""

  -- ignore macs with that pattern
  if not mac:find("00:00:00") then
  
    -- if we really cannot resolve anything, the hostname will be the mac by default
    local hostname = mac

    -- try userdef host mappings first
    local resolved = hosts[mac]

      -- Use cache if available next
    if not resolved and hostname_cache[mac] then
      resolved = hostname_cache[mac]
    end

    -- Try to resolve hostname via leases file next
    if not resolved and ip ~= "" then
      resolved = leases[ip] 
    end

    -- if none worked, try lookup (slowest)
    if not resolved or resolved == "" then
      local ns = io.popen("nslookup " .. ip .. " 2>/dev/null")
      local ns_output = ns:read("*a")
      ns:close()
      -- We expect a line like: <ipaddr>.in-addr.arpa     name = <host>.<domain>.
      -- So we remove the local domain part if present
      resolved = ns_output:match("name = ([^%s]+)%.?") or ""
      resolved = resolved:gsub(remove_local_domain, "")
    end

    -- final match
    if resolved and resolved ~= "" then
      hostname = resolved
      -- add discovered hostname to the cache
      hostname_cache[mac] = resolved
    else
      hostname = mac
    end

    n_conns = tonumber(line[4]) or 0
    n_rx_bytes = tonumber(line[5]) or 0
    n_rx_packets = tonumber(line[6]) or 0
    n_tx_bytes = tonumber(line[7]) or 0
    n_tx_packets = tonumber(line[8]) or 0
    if mac ~= "" and hostname ~= "" and n_conns >= 0 and n_rx_bytes >= 0 and n_rx_packets >= 0 and n_tx_bytes >= 0 and n_tx_packets >= 0 then
      -- Prepare InfluxDB line protocol entry
      -- print ("Processing MAC: " .. mac .. " IP: " .. ip .. " Hostname: " .. hostname .. " Conns: " .. n_conns .. " RX_Bytes: " .. n_rx_bytes .. " RX_Packets: " .. n_rx_packets .. " TX_Bytes: " .. n_tx_bytes .. " TX_Packets: " .. n_tx_packets .. " Timestamp: " .. timestamp)
      entry = format_influxdb_line_protocol(mac,ip,hostname,n_conns,n_rx_bytes,n_rx_packets,n_tx_bytes,n_tx_packets,timestamp)
      if (entry ~= nil) then
        table.insert(influxdb_entries, entry)
      end
    end

  -- end filter
  end
  --end for loop
end


-- Save updated cache
save_cache(hostname_cache)


-- Output Data
-- print(table.concat(influxdb_entries, ",\n"))
send_to_influxdb(table.concat(influxdb_entries, "\n"))

-- End of Script
