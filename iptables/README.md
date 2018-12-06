iptables Extension
==================

This extensions adds four tables:

* `iptables_ext`
* `ip6tables_ext`
* `iptables_policies`
* `ip6tables_policies`

## `iptables_ext` and `ip6tables_ext`

These tables bear resemblance to the core `iptables` table, with some key changes
(nonexhaustive):

* The `filter_name` column has been renamed to `table_name`.
* The `ruleno` column reflects the (1-based) index of a rule on a chain.
* The `protocol` column is `TEXT` rather than an `INTEGER`, via `getprotobynumber`.
* The `match` column provides a `TEXT` representation of all match entries, including
extensions added via `-m`.
* The `target_options` column provides a `TEXT` representation of the target's options,
such as packet rejection rules.
* `packets` and `bytes` are now `BIGINT`s to reflect their proper width, and a bug in
their retrieval in the core `iptables` table has been fixed.


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

## License

The code in this repository is licensed under the [Apache 2.0 license](../LICENSE).
