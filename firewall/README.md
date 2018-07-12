# fwctl osquery Extension

The fwctl extension provides osquery with the ability to view and _manage_ the OS-native firewall rules and `/etc/hosts` file (port and host blocking). Verify what your endpoints are blocking, and add new blocking rules as needed.

## Building

1. Install Boost
2. Clone the osquery repository
3. Symlink this extension into the external osquery directory. Use the following link name: "extension_fwctl".
4. Build osquery (see the [official building guide](https://osquery.readthedocs.io/en/latest/development/building/))
5. Run 'make externals'

## Installing Boost

macOS: `brew install boost`

Ubuntu: `apt install boost -y`

Windows: Open the official [Boost download page](http://www.boost.org/users/download/) and download `boost_1_66_0-msvc-14.0-64.exe` under [Boost - Third party downloads](https://dl.bintray.com/boostorg/release/1.66.0/binaries/).

## Running the automated tests

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

```bash
$ touch /etc/pf.anchors/osquery_firewall_pri
$ touch /etc/pf.anchors/osquery_firewall_sec
```

### Windows

No special requirements needed.

### Linux

No special requirements needed.

## Running the extension

To configure extensions on production environments, refer to the [official documentation](https://osquery.readthedocs.io/en/latest/deployment/extensions/). To perform a quick test, you can use the following command: 

```bash
$ osqueryi --allow_unsafe --disable_extensions=false --extension=/path/to/osquery/build/<platform_name>/extension_path.ext
```

All errors and messages are logged to the osquery status log (you can pass the `--verbose` option when using `osqueryi`). Inserting the same data more than once does not cause errors, and the rules will not be duplicated.

### Testing the extension

To test that the extension works as intended, we'll first verify that some ports and domains are unblocked, then block them via the extension and demonstrate that they're no longer accessible. Once lack of access is verified, we'll delete the rules we created and show that access to those ports and domains is restored.

#### Verify access

Open a web browser of your choice and verify that you can load:
* two websites that provide secure access, in this case https://www.yahoo.com and https://www.google.com
* a website that does not provide a secure connection, e.g., http://neverssl.com

Additionally, we need to verify that you're not running a web server locally. Attempt to load https://127.0.0.1 and verify that you get an error message (or take note of the page that is returned, if you are running a web server).

#### Block ports and domains

Follow the directions above to install the extension, then start up osqueryi with the extension running. At the prompt, issue the following commands:

``` sql
INSERT INTO HostBlacklist (domain, sinkhole, address_type) VALUES ("www.yahoo.com", "127.0.0.1", "ipv4");

INSERT INTO PortBlacklist (port, direction, protocol) VALUES (80, "OUTBOUND", "tcp");
```

Verify that these rules got created by running the following queries and checking their output against the output listed:
``` sql
SELECT domain, sinkhole, firewall_block, dns_block FROM HostBlacklist WHERE domain = "www.yahoo.com";
+---------------+-----------+----------------+-----------+
| domain        | sinkhole  | firewall_block | dns_block |
+---------------+-----------+----------------+-----------+
| www.yahoo.com | 127.0.0.1 | ENABLED        | ENABLED   |
+---------------+-----------+----------------+-----------+

SELECT * FROM PortBlacklist WHERE port = 80;
+------+-----------+----------+---------+
| port | direction | protocol | status  |
+------+-----------+----------+---------+
| 80   | OUTBOUND  | TCP      | ENABLED |
+------+-----------+----------+---------+
```

#### Verify lack of access

Open up a web browser, clear its cache, and attempt to load https://www.yahoo.com. You should get some sort of error page that the server is not responing, indicating that the host blocking is successful. If you're running a web server locally, you may see its page instead of yahoo's page. This also is an indicator that host blocking is successful.

Attempt to load https://www.google.com. This should be successful, indicating that secure connections to websites still work.

Now try to load http://neverssl.com. You should again get an error message, indicating that port 80 is blocked for outbound connections.

#### Delete rules and verify

Back in the osquery shell, run the following queries to delete the rules:

``` sql
DELETE FROM HostBlacklist WHERE domain = "www.yahoo.com";
DELETE FROM PortBlacklist WHERE port = 80;
```

Now attempt to load https://www.yahoo.com and http://neverssl.com again. They should all be successful, indicating that the rules were successfully deleted.

## Schema

### HostBlacklist

| Column         | Type | Description                                              |
|----------------|------|----------------------------------------------------------|
| address        | TEXT | The address of the host to block                         |
| domain         | TEXT | The domain to block                                      |
| sinkhole       | TEXT | The address that will be put in the hosts file           |
| firewall_block | TEXT | Firewall block status (address blocked by the firewall)  |
| dns_block      | TEXT | DNS block status (domain present in the hosts file)      |
| address_type   | TEXT | Address type (either ipv4 or ipv6). Only used on INSERTs |

When inserting data into the table, you can omit the `address` column to use the auto-resolver. The `address_type` (hidden) column can be used to decide whether to use IPv4 or IPv6. When omitting the `domain` column, a reverse lookup will be performed. Note that in this case the operation will fail if the entered domain is contained inside the hosts file. This is a precaution, in order to prevent users from blacklisting their own sinkholes by mistake.

This table has been enhanced to make use of the firewall to blacklist hosts; this is to make sure that once the domain has been entered into the hosts file, no further communication is allowed to those addresses (even for applications that resolved the IP address before the DNS block was enabled).

#### Special columns

The **address_type** column is only used on INSERTs, and can accept either `ipv4` or `ipv6`.

The **dns_block** and **firewall_block** columns return the state of the rule:
1. **ENABLED**: The rule has been applied correctly.
2. **DISABLED**: The rule is not applied either due to an error or because it may have been manually removed by the local administrator.
3. **UNMANAGED**: This (read only) rule was found on the system but was not added by osquery. The PF firewall supports private configuration namespaces, so this state does not apply on macOS.
4. **ALTERED** (only for dns_block): The rule is still present but it has been altered; this means that the domain is still present in the hosts file, but the sinkhole has been changed.

#### Example

Blocking a domain, specifying the address to add to the firewall:

``` sql
INSERT INTO HostBlacklist
  (domain, sinkhole, address)

VALUES
  ("www.google.com", "127.0.0.1", "12.34.56.78");
```

Blocking a domain, resolving the ip address automatically:

``` sql
INSERT INTO HostBlacklist
  (domain, sinkhole, address_type)

VALUES
  ("www.msdn.com", "127.0.0.1", "ipv4");
```

Checking the result of blocking a domain:

``` sql
SELECT * FROM HostBlacklist
WHERE domain = "www.msdn.com";

+-------------+--------------+-----------+----------------+-----------+
| address     | domain       | sinkhole  | firewall_block | dns_block |
+-------------+--------------+-----------+----------------+-----------+
| 23.96.52.53 | www.msdn.com | 127.0.0.1 | ENABLED        | ENABLED   |
+-------------+--------------+-----------+----------------+-----------+
```

Unblocking a domain:

``` sql
DELETE FROM HostBlacklist
WHERE domain = "www.msdn.com";
```

Please note that a domain may be reachable with several ip addresses that may not even be listed at all when performing a reverse lookup; it is best to always specify the address manually to make sure that the right one is selected.

### PortBlacklist

| Column         | Type | Description                                    |
|----------------|------|------------------------------------------------|
| port           | TEXT | The port to block (1 - 65535)                  |
| direction      | TEXT | Traffic direction; either INBOUND or OUTBOUND  |
| protocol       | TEXT | Either TCP or UDP                              |
| status         | TEXT | Firewall block status                          |

#### Example

Block (inbound) SSH access to the machine:

``` sql
INSERT INTO PortBlacklist
  (port, direction, protocol)

VALUES
  (22, "INBOUND", "TCP");
```

Block (outbound) access to HTTP websites:

``` sql
INSERT INTO PortBlacklist
  (port, direction, protocol)

VALUES
  (80, "OUTBOUND", "TCP");
```

Checking the result of blocking a port:

``` sql
SELECT * FROM PortBlacklist
WHERE port = 80;

+------+-----------+----------+---------+
| port | direction | protocol | status  |
+------+-----------+----------+---------+
| 80   | OUTBOUND  | TCP      | ENABLED |
+------+-----------+----------+---------+
```

Unblocking a port:

``` sql
DELETE FROM PortBlacklist
WHERE port = 80;
```

#### Special columns

The **status** column return the state of the rule:

1. **ENABLED**: The rule has been applied correctly.
2. **DISABLED**: The rule is not applied either due to an error or because it may have been manually removed by the local administrator.
3. **UNMANAGED**: This (read only) rule was found on the system but was not added by osquery. The PF firewall supports private configuration namespaces, so this state does not apply on macOS.

## Additional notes

### Duplicate INSERTs or DELETEs

The extension is designed to be permissive in what it accepts: attempting to INSERT a rule that already exists will silently do nothing, and likewise attempting to DELETE a rule that doesn't exist will silently do nothing. 

## License

The code in this repository is licensed under the [Apache 2.0 license](../LICENSE).
