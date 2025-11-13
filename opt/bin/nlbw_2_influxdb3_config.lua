-- CONFIGURATION FILE FOR nlbw_2_influxdb3.lua

local config = {
    -- **Cache file path: pick a temp file name**
    cache_file_path = "/tmp/nlbw_2_influxdb3.maclist.json",
    -- **User mac to host name mapping file**
    user_list_path = "./nlbw_2_influxdb3.maclist.txt",
    -- **this is the local domain that will be removed from any nslookup hostnames**
    -- this could be .local, .localdomain, .home.arpa, etc.
    remove_local_domain = ".localdomain",

    -- **InfluxDB Configuration**
    -- change for your ip address or hostname and port
    -- change to your databse, keep the second precision
    influxdb_url = "http://<ip address>:8181/api/v3/write_lp?db=<your database name here>&precision=second",
    -- replace by your token
    influxdb_token = "your_influxdb_token_here",
}

return config
