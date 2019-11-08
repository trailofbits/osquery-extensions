

#pragma once

#include <linux/types.h>
#include <libiptc/ipt_kernel_headers.h>
#ifdef __cplusplus
#       include <climits>
#else
#       include <limits.h> /* INT_MAX in ip6_tables.h */
#endif

#include <linux/if.h>
#include <linux/netfilter_ipv6.h>

#include <linux/netfilter/x_tables.h>

#define IP6T_FUNCTION_MAXNAMELEN XT_FUNCTION_MAXNAMELEN
#define IP6T_TABLE_MAXNAMELEN XT_TABLE_MAXNAMELEN
#define ip6t_match xt_match
#define ip6t_target xt_target
#define ip6t_table xt_table
#define ip6t_get_revision xt_get_revision
#define ip6t_entry_match xt_entry_match
#define ip6t_entry_target xt_entry_target
#define ip6t_standard_target xt_standard_target
#define ip6t_error_target xt_error_target
#define ip6t_counters xt_counters
#define IP6T_CONTINUE XT_CONTINUE
#define IP6T_RETURN XT_RETURN

/* Pre-iptables-1.4.0 */
#include <linux/netfilter/xt_tcpudp.h>
#define ip6t_tcp xt_tcp
#define ip6t_udp xt_udp
#define IP6T_TCP_INV_SRCPT      XT_TCP_INV_SRCPT
#define IP6T_TCP_INV_DSTPT      XT_TCP_INV_DSTPT
#define IP6T_TCP_INV_FLAGS      XT_TCP_INV_FLAGS
#define IP6T_TCP_INV_OPTION     XT_TCP_INV_OPTION
#define IP6T_TCP_INV_MASK       XT_TCP_INV_MASK
#define IP6T_UDP_INV_SRCPT      XT_UDP_INV_SRCPT
#define IP6T_UDP_INV_DSTPT      XT_UDP_INV_DSTPT
#define IP6T_UDP_INV_MASK       XT_UDP_INV_MASK

#define ip6t_counters_info xt_counters_info
#define IP6T_STANDARD_TARGET XT_STANDARD_TARGET
#define IP6T_ERROR_TARGET XT_ERROR_TARGET

/* Yes, Virginia, you have to zero the padding. */
struct ip6t_ip6 {
  /* Source and destination IP6 addr */
  struct in6_addr src, dst;
  /* Mask for src and dest IP6 addr */
  struct in6_addr smsk, dmsk;
  char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
  unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];

  /* Upper protocol number
   * - The allowed value is 0 (any) or protocol number of last parsable
   *   header, which is 50 (ESP), 59 (No Next Header), 135 (MH), or
   *   the non IPv6 extension headers.
   * - The protocol numbers of IPv6 extension headers except of ESP and
   *   MH do not match any packets.
   * - You also need to set IP6T_FLAGS_PROTO to "flags" to check protocol.
   */
  __u16 proto;
  /* TOS to match iff flags & IP6T_F_TOS */
  __u8 tos;

  /* Flags word */
  __u8 flags;
  /* Inverse flags */
  __u8 invflags;
};

/* Values for "flag" field in struct ip6t_ip6 (general ip6 structure). */
#define IP6T_F_PROTO            0x01    /* Set if rule cares about upper
                                           protocols */
#define IP6T_F_TOS              0x02    /* Match the TOS. */
#define IP6T_F_GOTO             0x04    /* Set if jump is a goto */
#define IP6T_F_MASK             0x07    /* All possible flag bits mask. */

/* Values for "inv" field in struct ip6t_ip6. */
#define IP6T_INV_VIA_IN         0x01    /* Invert the sense of IN IFACE. */
#define IP6T_INV_VIA_OUT                0x02    /* Invert the sense of OUT IFACE */
#define IP6T_INV_TOS            0x04    /* Invert the sense of TOS. */
#define IP6T_INV_SRCIP          0x08    /* Invert the sense of SRC IP. */
#define IP6T_INV_DSTIP          0x10    /* Invert the sense of DST OP. */
#define IP6T_INV_FRAG           0x20    /* Invert the sense of FRAG. */
#define IP6T_INV_PROTO          XT_INV_PROTO
#define IP6T_INV_MASK           0x7F    /* All possible flag bits mask. */

/* This structure defines each of the firewall rules.  Consists of 3
   parts which are 1) general IP header stuff 2) match specific
   stuff 3) the target to perform if the rule matches */

struct ip6t_entry {
  struct ip6t_ip6 ipv6;

  /* Mark with fields that we care about. */
  unsigned int nfcache;

  /* Size of ipt_entry + matches */
  __u16 target_offset;
  /* Size of ipt_entry + matches + target */
  __u16 next_offset;

  /* Back pointer */
  unsigned int comefrom;

  /* Packet and byte counters. */
  struct xt_counters counters;

  /* The matches (if any), then the target. */
  unsigned char elems[0];
};

#include <libiptc/xtcshared.h>

#define ip6tc_handle xtc_handle
#define ip6t_chainlabel xt_chainlabel

#define IP6TC_LABEL_ACCEPT "ACCEPT"
#define IP6TC_LABEL_DROP "DROP"
#define IP6TC_LABEL_QUEUE   "QUEUE"
#define IP6TC_LABEL_RETURN "RETURN"

/* Does this chain exist? */
extern int ip6tc_is_chain(const char *chain, struct xtc_handle *const handle);

/* Take a snapshot of the rules. Returns NULL on error. */
extern struct xtc_handle *ip6tc_init(const char *tablename);

/* Cleanup after ip6tc_init(). */
extern void ip6tc_free(struct xtc_handle *h);

/* Iterator functions to run through the chains.  Returns NULL at end. */
extern const char *ip6tc_first_chain(struct xtc_handle *handle);
extern const char *ip6tc_next_chain(struct xtc_handle *handle);

/* Get first rule in the given chain: NULL for empty chain. */
extern const struct ip6t_entry *ip6tc_first_rule(const char *chain,
                                          struct xtc_handle *handle);

/* Returns NULL when rules run out. */
extern const struct ip6t_entry *ip6tc_next_rule(const struct ip6t_entry *prev,
                                         struct xtc_handle *handle);

/* Returns NULL when rules run out. */
extern const struct ip6t_entry *ip6tc_next_rule(const struct ip6t_entry *prev,
                                         struct xtc_handle *handle);

/* Returns a pointer to the target name of this position. */
extern const char *ip6tc_get_target(const struct ip6t_entry *e,
                             struct xtc_handle *handle);

/* Is this a built-in chain? */
extern int ip6tc_builtin(const char *chain, struct xtc_handle *const handle);

/* Get the policy of a given built-in chain */
extern const char *ip6tc_get_policy(const char *chain,
                             struct xt_counters *counters,
                             struct xtc_handle *handle);
