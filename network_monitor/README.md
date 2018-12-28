# Introduction
This is an experimental extension that provides a `dns_events` table that lists the DNS requests and answers happening on the endpoint.

# Configuration options
The configuration file is located at the following path: `/var/osquery/extensions/com/trailofbits/network_monitor.json`

``` json
{
  "user": "tob_network_monitor_ext",

  "dns_events": {
    "interface": "eth0"
  }
}
```

The `user` setting is used when dropping privileges and is mandatory.

# Dropping privileges
During startup, the extension will perform the following tasks:

1. Read the configuration file
2. Request to osquery where the extension manager socket is located
3. Update the extensions socket permissions (root:config.user, 770)
4. Initialize and activate the Pcap handle
5. Drop privileges
6. Start the normal event loop
7. If the configuration changes, then the extension will print a warning message and quit. The osquery watchdog is expected to be turned on in order to have the extension go through these steps from the start.
