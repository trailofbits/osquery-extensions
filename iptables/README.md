iptables Extension
==================

This extensions adds four tables:

* `iptables_ext`
* `ip6tables_ext`
* `iptables_policies`
* `ip6tables_policies`

## `iptables_ext` and `ip6tables_ext`

These tables bear some resemblance to the `iptables` table in osquery core, but with some key changes, including:

* The `filter_name` column has been renamed to `table_name`.
* The `ruleno` column reflects the (1-based) index of a rule on a chain.
* The `protocol` column is `TEXT` rather than an `INTEGER`, via `getprotobynumber`.
* The `match` column provides a `TEXT` representation of all match entries, including
extensions added via `-m`.
* The `target_options` column provides a `TEXT` representation of the target's options,
such as packet rejection rules.
* `packets` and `bytes` are now `BIGINT`s to reflect their proper width, and a bug in
their retrieval in the core `iptables` table has been fixed.

These tables are not a superset of the information in the `iptables` table. They complement, not replace, the core osquery functionality.

### Schema

| Column         | Type    | Description                                              |
|:---------------|:--------|:---------------------------------------------------------|
| table_name     | TEXT    | Packet matching table name.                              |
| chain          | TEXT    | Name of the chain.                                       |
| ruleno         | INTEGER | (1-based) index of this rule within the table and chain. |
| target         | TEXT    | Name of the match target.                                |
| target_options | TEXT    | Any options associated with the target.                  |
| match          | TEXT    | A string representation of the rule's match entries.     |
| protocol       | TEXT    | Matched protocol, e.g. `tcp`.                            |
| src_port       | TEXT    | Source port range.                                       |
| dst_port       | TEXT    | Destination port range.                                  |
| src_ip         | TEXT    | Source IP address.                                       |
| src_mask       | TEXT    | Source IP's mask.                                        |
| iniface        | TEXT    | Inbound interface.                                       |
| iniface_mask   | TEXT    | Inbound interface's mask.                                |
| dst_ip         | TEXT    | Destination IP address                                   |
| dst_mask       | TEXT    | Destination IP's mask.                                   |
| outiface       | TEXT    | Outbound interface.                                      |
| outiface_mask  | TEXT    | Outbound interface's mask.                               |
| packets        | BIGINT  | The number of packets evaluated by the rule.             |
| bytes          | BIGINT  | The number of bytes evaluated by the rule.               |

### Usage

```sql
SELECT * from iptables_ext;
SELECT * from ip6tables_ext where target = "ACCEPT";
```

If the results are empty, you may not have any iptables chains defined. To demonstrate, we will first append some iptables rules to a chain, and then use osquery to display it:

```shell
$ sudo iptables -A INPUT -p tcp -s localhost --dport 25 -j ACCEPT
$ sudo iptables -A INPUT -p tcp --dport 25 -j DROP
```

```
osquery> .mode line
osquery> select * from iptables_ext;
    table_name = filter
         chain = INPUT
        ruleno = 1
        target = ACCEPT
target_options = 
         match = -m tcp --dport 25
      protocol = tcp
      src_port = 0:65535
      dst_port = 25:25
        src_ip = 127.0.0.1
      src_mask = 255.255.255.255
       iniface = all
  iniface_mask = 
        dst_ip = 0.0.0.0
      dst_mask = 0.0.0.0
      outiface = all
 outiface_mask = 
       packets = 0
         bytes = 0

    table_name = filter
         chain = INPUT
        ruleno = 2
        target = DROP
target_options = 
         match = -m tcp --dport 25
      protocol = tcp
      src_port = 0:65535
      dst_port = 25:25
        src_ip = 0.0.0.0
      src_mask = 0.0.0.0
       iniface = all
  iniface_mask = 
        dst_ip = 0.0.0.0
      dst_mask = 0.0.0.0
      outiface = all
 outiface_mask = 
       packets = 0
         bytes = 0
```

## `iptables_policies` and `ip6tables_policies`

### Schema

| Column      | Type   | Description                                          |
|:------------|:-------|:-----------------------------------------------------|
| table_name  | TEXT   | Packet matching table name.                          |
| chain       | TEXT   | Name of the chain.                                   |
| policy      | TEXT   | The chain's default policy.                          |
| packets     | BIGINT | The number of packets handled by the chain's policy. |
| bytes       | BIGINT | The number of bytes handled by the chain's policy.   |

### Usage

```sql
SELECT * from ip6tables_policies;
SELECT packets from iptables_policies where table_name = "nat";
```

## Troubleshooting

When running osquery with `--verbose`, if you see messages like the following, you may not have IPv6 configured on your system. This is not a bug in the tables.

```
I1113 11:46:59.341866 37216 ip6tables_ext.cpp:43] Error fetching matches from ip6tables-save: no output from command
I1113 11:46:59.342032 37216 utils.cpp:61] Error reading: /proc/net/ip6_tables_names: Cannot open file for reading: /proc/net/ip6_tables_names
o
```

You might confirm whether this is the case:

```shell
[ ! -f /proc/net/ip6_tables_names ] && echo "Current kernel doesn't support 'ip6tables' firewalling (IPv6)!"
```

## License

The code in this repository is licensed under the [Apache 2.0 license](../LICENSE).
