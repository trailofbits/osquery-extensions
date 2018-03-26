# fwctl osquery Extension

The firewall extension provides osquery with the capability to block ports and blacklist hosts. It makes use of the native firewall 
## Building

1. Install Boost
2. Clone the osquery repository
3. Symlink this extension into the external osquery directory. Use the following link name: "extension_fwctl".
4. Build osquery (see the [official building guide](https://osquery.readthedocs.io/en/latest/development/building/))
5. Run 'make externals'

## Installing Boost
MacOS: `brew install boost`
Ubuntu: `apt install boost -y`
Windows: Open the official [Boost download page](http://www.boost.org/users/download/) and download `boost_1_66_0-msvc-14.0-64.exe` under [Boost - Third party downloads](https://dl.bintray.com/boostorg/release/1.66.0/binaries/).

## Running the tests

Once osquery has been built with tests enabled (i.e.: *without* the SKIP_TESTS variable), enter the build/<platform_name> folder and run the following command: `make fwctl_tests`.

## Installation

### macOS

Enable the osquery PF anchors, by adding the following lines in your `/etc/pf.conf` file:
```
....
anchor "com.apple/*" # Keep this entry above your settings

anchor osquery_firewall_pri
load anchor osquery_firewall_pri from "/etc/pf.anchors/osquery_firewall_pri"

anchor osquery_firewall_sec
load anchor osquery_firewall_sec from "/etc/pf.anchors/osquery_firewall_sec"
```

Create the anchor files:

```
touch /etc/pf.anchors/osquery_firewall_pri
touch /etc/pf.anchors/osquery_firewall_sec
```

### Windows

No special requirements needed.

### Linux

No special requirements needed.

## Running the extension

Refer to the [official documentation](https://osquery.readthedocs.io/en/latest/deployment/extensions/) for more information on the matter. To perform a quick test, you can use the following command: `osqueryi --disable_extensions=false --extension=/path/to/osquery/build/<platform_name>/extension_path.ext`.

## Schema

### HostBlacklist

| Column         | Type | Description                                              |
|----------------|------|----------------------------------------------------------|
| address        | TEXT | The address of the host to block                         |
| domain         | TEXT | The domain to block                                      |
| sinkhole       | TEXT | The address that will be put in the hosts file           |
| firewall_block | TEXT | Firewall block status                                    |
| dns_block      | TEXT | DNS block status                                         |
| address_type   | TEXT | Address type (either ipv4 or ipv6). Only used on INSERTs |

When inserting data into the table, you can omit the `address` column to use the auto-resolver. The `address_type` (hidden) column can be used to decide whether to use IPv4 or IPv6. When omitting the `domain` column, a reverse lookup will be performed. Note that in this case the operation will fail if the entered domain is contained inside the hosts file. This is a precaution, in order to prevent users from blacklisting their own sinkholes by mistake.

This table has been enhanced to make use of the firewall to blacklist hosts; this is to make sure that once the domain has been entered into the hosts file, no further communication is allowed to those addresses (even for applications that resolved the IP address before the DNS block was enabled).

### PortBlacklist

| Column         | Type | Description                                    |
|----------------|------|------------------------------------------------|
| port           | TEXT | The port to block (1 - 65535)                  |
| direction      | TEXT | Traffic direction; either INBOUND or OUTBOUND  |
| protocol       | TEXT | Either TCP or UDP                              |
| status         | TEXT | Firewall block status                          |

## License

The code in this repository is licensed under the [Apache 2.0 license](../LICENSE).
