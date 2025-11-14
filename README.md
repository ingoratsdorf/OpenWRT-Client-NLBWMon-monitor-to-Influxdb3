# OpenWRT-Client-NLBWMon-monitor-to-Influxdb3
Dumps client connection details from NLBWMon to InfluxDB3 via its line write backend

### Prerequisites

This is obviously intended to be used to gather data for Influxdb V3 server, so you must have Influxdb server installed somewhere in some manner.
For configuration of Influxdb server, please refer to the Influxdb documentation: https://docs.influxdata.com/influxdb3/enterprise/install/
This has been tested with the current version 3.6 installed as LXC in Proxmox. Should work with any Influxdb v3 server.

You must have `luci-app-nlbwmon`, `lua` and `sudo` installed on your OpenWRT device (Use a terminal or the browser UI), also `luasocket` and `lua-cjson`.
```
    opkg update
    opkg install luci-app-nlbwmon
    opkg install sudo lua luasocket lua-cjson
```
Explanation:

`luci-app-nlbwmon` is installing `nlbwmon` and `nlbw` packages as dependencies. Those are measuring the forwards from lan to wan.

In theory, you only need to install nlwbmon, that does do all the work we need it to do, but the luci app is an easy and nice way if configuring the monitor.

It can also provide a nice UI as a control if everything is working as intended.


### Installation

* create `/opt/bin` director: `mkdir /opt/bin`.
* copy the `nlbw_2_influxdb3.lua` file into `/opt/bin` directory.
* Make it executable: `chmod +x nlbw_2_influxdb3.lua`.
* Optional: create a file `nlbw_2_influxdb3.maclist.txt` in the same directory. You can copy the template provided.
* change the config in file `nlbw_2_influxdb3_config.lua` to suit your needs
* Add it to the chrontab in the OpenWRT UI under 'System' -> 'Scheduled Tasks', suggested every 5-15 minutes to avoiud collecting too much data, but that's up to you:
```
# Run nlwbmon updates every 5 min
*/5 * * * * cd /opt/bin && /opt/bin/nlbw_2_influxdb3.lua
```
Done!

It's important that you cd into its working directory, otherwise the config file cannot be found.
There are (complicated) ways of retrieviung the module path but why doing a lot of calls and math and string parsing when this just does the trick.

If you want, you can do a testrun executing `./nlbw_2_influxdb3.lua` in your shell. Check if all runs.
