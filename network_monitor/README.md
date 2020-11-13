# Introduction
This is an experimental extension that provides a `dns_events` table that lists the DNS requests and answers happening on the endpoint.

# Usage

Note that the `network_monitor` extension, because it drops its privileges at runtime, is not compatible with being bundled together in the single extension with others. It is built and loaded separately from its own extension file, `network_monitor.ext`.

## Configuration options
The configuration file is located at the following path: `/var/osquery/extensions/com/trailofbits/network_monitor.json`

``` json
{
  "user": "tob_network_monitor_ext",

  "dns_events": {
    "interface": "eth0",
    "promiscuous": false,

    "max_tcp_conversation_length": 10240,
    "max_tcp_conversation_idle_time": 300
  }
}
```

**user**: This user will be used to drop privileges.  
**interface**: Interface to monitor. Currently, only one is supported.  
**promiscuous**: If enabled, the table will also be able to report DNS requests/answers from other machines on the same network. **You should always consult the network administrator when enabling this setting!**  
**max_tcp_conversation_length**: TCP conversations that are bigger than this amount of bytes will be ignored.  
**max_tcp_conversation_idle_time**: TCP conversations that have been idle for this amount of seconds will be ignored.  

# Dropping privileges

During startup, the extension will perform the following tasks:

1. Read the configuration file
2. Request to osquery where the extension manager socket is located
3. Update the extensions socket permissions (root:config.user, 770)
4. Initialize and activate the Pcap handle
5. Drop privileges
6. Start the normal event loop
7. If the configuration changes, then the extension will print a warning message and quit. The osquery watchdog is expected to be turned on in order to have the extension go through these steps from the start.
