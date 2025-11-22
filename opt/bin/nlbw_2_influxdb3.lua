#!/usr/bin/env lua

-- IMPORTS
local socket = require("socket")  -- Requires luasocket, opkg install luasocket
local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("cjson")  -- Requires cjson, opkg install lua-cjson

DEBUG_PREFIX = "[nlbw_2_influxdb3] "

-- DEBUGGING helper function
local function dump(o)
  if type(o) == 'table' then
    local s = '{ '
    for k,v in pairs(o) do
      if type(k) ~= 'number' then k = '"'..k..'"' end
      s = s .. '['..k..'] = ' .. dump(v) .. ','
    end
    return s .. '} '
  else
    return tostring(o)
  end
end

local function sleep(sec)
  socket.select(nil, nil, sec)
end

--[[
Read and restore the cache used by the monitor from JSON string in user specified file.
Returns:
@return array of tuples, essentially [mac_address, hostname]
]]
local function load_cache()
  local cache = {}
  if (CACHE_FILE_PATH) then
    
    local f = io.open(CACHE_FILE_PATH, "r")
    if f then
      local content = f:read("*a")
      f:close()
      cache = json.decode(content) or {}
    end
  end
  return cache
end

--[[
Save hostname cache
Saves cache to user specified file as a json string
Returns:
@return array of tuples, essentially [mac_address, hostname]
]]
local function save_cache(cache)
  if (CACHE_FILE_PATH) then
    local f = io.open(CACHE_FILE_PATH, "w")
    if f then
      f:write(json.encode(cache))
      f:close()
    end
  end
end

--[[
Load and normalize lease information from system lease sources.
This function collects associations between MAC addresses, IP addresses and hostnames
by parsing available DHCP lease files
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

--[[
try the user defined user_defined_hosts file file for custom hostnames
this file should contain lines like:
00:11:22:33:44:55 mydevice
where the first part is the MAC address and the second part is the hostname
this allows users to define custom names for devices that may not have a hostname
or to override the default hostname resolution
the file should be placed in the same directory as this script
and should be readable by the user running this script
]]
local function load_user_defined_hosts()
  local user_defined_hosts = {}
  if (USER_LIST_PATH) then
    local host_file = io.open(USER_LIST_PATH, "r")
    if host_file then
      for line in host_file:lines() do
        local mac, name = line:match("^(%S+)%s+(%S+)")
        if mac and name then
          user_defined_hosts[string.lower(mac)] = name
        end
      end
      host_file:close()
    end
  end
  return user_defined_hosts
end


--[[
Format Data for InfluxDB
]]
local function format_influxdb_line_protocol(mac,ip,hostname,conns,rx_bytes,rx_packets,tx_bytes,tx_packets, timestamp)
    -- Line protocol format: measurement,tag=value field=value timestamp
    return string.format(
        "nlbwmon_traffic,mac=%s,ip=%s,hostname=%s conns=%.0fu,rx_bytes=%.0fu,rx_packets=%.0fu,tx_bytes=%.0fu,tx_packets=%.0fu %.0f",
        mac, ip, hostname, conns, rx_bytes, rx_packets, tx_bytes, tx_packets, timestamp
    )
end

--[[
Send Data to InfluxDB
]]
local function send_to_influxdb(payload)
  if (INFLUXDB_URL == "" or INFLUXDB_TOKEN == "") then
    print(DEBUG_PREFIX .. "InfluxDB URL or Token not set. Skipping data send.")
    return
  end
  local response_body = {}
  local res, code, headers, status = http.request{
    url = INFLUXDB_URL,
    method = "POST",
    headers = {
        ["Authorization"] = "Bearer " .. INFLUXDB_TOKEN,
        ["Content-Type"] = "text/plain",
        ["Content-Length"] = tostring(#payload)
    },
    source = ltn12.source.string(payload),
    sink = ltn12.sink.table(response_body)
  }

  if code == 204 then
    if DEBUG then print(DEBUG_PREFIX .. "Data successfully sent to InfluxDB.") end
  else
    print(DEBUG_PREFIX .. "Failed to send data to InfluxDB. HTTP Code: " .. tostring(code))
    print(DEBUG_PREFIX .. "Response: " .. table.concat(response_body))
  end
end


--[[
Run the nlbw command and capture output
This returns lines like in a json structure with fields:
{"columns":["family","mac","ip","conns","rx_bytes","rx_pkts","tx_bytes","tx_pkts"],"data":[ [ .. ] ]}
]]
local function process_nlbw_data()

  -- load local cache
  local hostname_cache = load_cache()
  -- Load DHCP leases into a lookup table
  local leases = load_leases()
  -- Load user-defined host mappings
  local user_defined_hosts = load_user_defined_hosts()

  local timestamp = os.time()
  local handle = io.popen("sudo nlbw -c json -n -g mac,ip,fam -q")
  if (not handle) then
    print(DEBUG_PREFIX .. "Failed to run nlbw command.")
    return {}
  end
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
      local resolved_hostname = user_defined_hosts[mac]

        -- Use cache if available next
      if not resolved_hostname and hostname_cache[mac] then
        resolved_hostname = hostname_cache[mac]
      end

      -- Try to resolve hostname via leases file next
      if not resolved_hostname and ip ~= "" then
        resolved_hostname = leases[ip] 
      end

      -- if none worked, try lookup (slowest)
      if not resolved_hostname or resolved_hostname == "" then
        local ns = io.popen("nslookup " .. ip .. " 2>/dev/null")
        if (ns) then
          local ns_output = ns:read("*a")
          ns:close()
        
          -- We expect a line like: <ipaddr>.in-addr.arpa     name = <host>.<domain>.
          -- So we remove the local domain part if present
          resolved_hostname = ns_output:match("name = ([^%s]+)%.?") or ""
        end -- if ns
      end

      -- remove local domain if present
      resolved_hostname = resolved_hostname:gsub(REMOVE_LOCAL_DOMAIN, "")

      -- final match
      if resolved_hostname and resolved_hostname ~= "" then
        hostname = resolved_hostname
        -- add discovered hostname to the cache
        hostname_cache[mac] = resolved_hostname
        -- Save updated cache
        save_cache(hostname_cache)
      else
        hostname = mac
      end

      local n_conns = tonumber(line[4]) or 0
      local n_rx_bytes = tonumber(line[5]) or 0
      local n_rx_packets = tonumber(line[6]) or 0
      local n_tx_bytes = tonumber(line[7]) or 0
      local n_tx_packets = tonumber(line[8]) or 0
      if mac ~= "" and hostname ~= "" then

        if DEBUG then print (DEBUG_PREFIX .. "Processing MAC values: " .. mac .. " IP: " .. ip .. " Hostname: " .. hostname .. " Conns: " .. n_conns .. " RX_Bytes: " .. n_rx_bytes .. " RX_Packets: " .. n_rx_packets .. " TX_Bytes: " .. n_tx_bytes .. " TX_Packets: " .. n_tx_packets .. " Timestamp: " .. timestamp) end

        -- save state in cache (last value cache)
        local mac_cache = LVC[mac]
        local last_values = nil
        if (mac_cache) then
          last_values = mac_cache[ip] or nil
        end

        if (last_values) then

          if DEBUG then print (DEBUG_PREFIX .. "Processing MAC LVC: " .. mac .. " IP: " .. ip .. " Hostname: " .. hostname .. " Conns: " .. last_values.conns .. " RX_Bytes: " .. last_values.rx_bytes .. " RX_Packets: " .. last_values.rx_packets .. " TX_Bytes: " .. last_values.tx_bytes .. " TX_Packets: " .. last_values.tx_packets .. " Timestamp: " .. timestamp) end

          -- calulate deltas
          -- allow for counter resets
          local n_conns_d = 0
          if (n_conns > last_values.conns) then
            n_conns_d = n_conns - last_values.conns
          end
          local n_rx_bytes_d = 0
          if (n_rx_bytes > last_values.rx_bytes) then
            n_rx_bytes_d = n_rx_bytes - last_values.rx_bytes  
          end
          local n_rx_packets_d = 0
          if (n_rx_packets > last_values.rx_packets) then
            n_rx_packets_d = n_rx_packets - last_values.rx_packets
          end
          local n_tx_bytes_d = 0
          if (n_tx_bytes > last_values.tx_bytes) then
            n_tx_bytes_d = n_tx_bytes - last_values.tx_bytes
          end
          local n_tx_packets_d = 0
          if (n_tx_packets > last_values.tx_packets) then
            n_tx_packets_d = n_tx_packets - last_values.tx_packets
          end

          -- only send positive deltas
          if n_conns_d >= 0 and n_rx_bytes_d >= 0 and n_rx_packets_d >= 0 and n_tx_bytes_d >= 0 and n_tx_packets_d >= 0 then

            -- only send if at least one value is not 0
            if (n_conns_d > 0 or n_rx_bytes_d > 0 or n_rx_packets_d > 0 or n_tx_bytes_d > 0 or n_tx_packets_d > 0) then

              -- Prepare InfluxDB line protocol entry
              if DEBUG then print (DEBUG_PREFIX .. "Processing MAC deltas: " .. mac .. " IP: " .. ip .. " Hostname: " .. hostname .. " Conns: " .. n_conns_d .. " RX_Bytes: " .. n_rx_bytes_d .. " RX_Packets: " .. n_rx_packets_d .. " TX_Bytes: " .. n_tx_bytes_d .. " TX_Packets: " .. n_tx_packets_d .. " Timestamp: " .. timestamp) end

              local entry = format_influxdb_line_protocol(mac,ip,hostname,n_conns_d,n_rx_bytes_d,n_rx_packets_d,n_tx_bytes_d,n_tx_packets_d,timestamp)
              if (entry ~= nil) then
                table.insert(influxdb_entries, entry)
              end --  if entry
            end -- if n_conns_d > 0 ...
          end -- if n_conns ...

        else
          if DEBUG then print (DEBUG_PREFIX .. "No last values for MAC: " .. mac .. ", skipping delta calculation.") end
        end -- if last_values

        -- save LVC
        if LVC[mac] == nil then
          LVC[mac] = {}
        end
        LVC[mac][ip] = {
          conns = n_conns,
          rx_bytes = n_rx_bytes,
          rx_packets = n_rx_packets,
          tx_bytes = n_tx_bytes,
          tx_packets = n_tx_packets,
          timestamp = timestamp
        }
      end -- if mac ...
    end -- if not mac:find ...
  end -- for each line
  return influxdb_entries
end -- process_nlbw_data




CACHE_FILE_PATH="/tmp/nlbw_2_influxdb3.maclist.json"
USER_LIST_PATH="/opt/bin/nlbw_2_influxdb3.maclist.txt"
REMOVE_LOCAL_DOMAIN = ".localdomain"
INFLUXDB_URL = ""
INFLUXDB_TOKEN = ""
LVC = {} -- Last Value Cache
DEBUG = false -- debugging enabled / disabled
INTERVAL_SECONDS = 300  -- default to 5 minutes

local function parse_args()
  local args = {}
  for _, v in ipairs(arg) do
    local key, value = v:match("^([%w_]+)=([%w%p_%-%.]+)$")
    if key and value then
      if (key == "cache_file_path") then
        print(DEBUG_PREFIX .. "Using cache file path: " .. value)
        CACHE_FILE_PATH = value
      elseif (key == "user_list_path") then
        print(DEBUG_PREFIX .. "Using user list path: " .. value)
        USER_LIST_PATH = value
      elseif (key == "remove_local_domain") then
        print(DEBUG_PREFIX .. "Removing local domain " .. value)
        REMOVE_LOCAL_DOMAIN = value
      elseif (key == "influxdb_url") then
        print(DEBUG_PREFIX .. "Using InfluxDB URL: " .. value)
        INFLUXDB_URL = value
      elseif (key == "influxdb_token") then
        print(DEBUG_PREFIX .. "Using InfluxDB Token: ********")
        INFLUXDB_TOKEN = value
      elseif (key == "debug") then
        DEBUG = (value == "true" or value == "1")
        print(DEBUG_PREFIX .. "Debug mode set to: " .. tostring(DEBUG))
      elseif (key == "interval") then
        local interval = tonumber(value)
        if interval and interval > 0 then
          print(DEBUG_PREFIX .. "Setting interval to: " .. tostring(interval) .. " seconds")
          INTERVAL_SECONDS = interval
        else
          print(DEBUG_PREFIX .. "Invalid interval value: " .. tostring(value))
          print(DEBUG_PREFIX .. "Keeping default interval value of: " .. tostring(INTERVAL_SECONDS))
        end -- if interval
      else
        print(DEBUG_PREFIX .. "Got unknown argument: " .. v)
      end -- if key ...
    end -- if key ...
  end -- for
end -- function

-- Load command line arguments
parse_args()

--[[
Main Loop
]]
while true do

  -- current timestamp
  local influxdb_entries = process_nlbw_data()

  -- Output Data
  -- print(DEBUG_PREFIX .. table.concat(influxdb_entries, ",\n"))
  send_to_influxdb(table.concat(influxdb_entries, "\n"))

  sleep(INTERVAL_SECONDS)  -- wait for 5 minutes before next run

end -- while true

-- End of Script
