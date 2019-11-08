/*
 * Copyright (c) 2019 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#pragma once

#include <linux/types.h>
#include <libiptc/ipt_kernel_headers.h>
#ifdef __cplusplus
#       include <climits>
#else
#       include <limits.h> /* INT_MAX in ip_tables.h */
#endif
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>

#define IPT_FUNCTION_MAXNAMELEN XT_FUNCTION_MAXNAMELEN
#define IPT_TABLE_MAXNAMELEN XT_TABLE_MAXNAMELEN
#define ipt_match xt_match
#define ipt_target xt_target
#define ipt_table xt_table
#define ipt_get_revision xt_get_revision
#define ipt_entry_match xt_entry_match
#define ipt_entry_target xt_entry_target
#define ipt_standard_target xt_standard_target
#define ipt_error_target xt_error_target
#define ipt_counters xt_counters
#define IPT_CONTINUE XT_CONTINUE
#define IPT_RETURN XT_RETURN

/* This group is older than old (iptables < v1.4.0-rc1~89) */
#include <linux/netfilter/xt_tcpudp.h>
#define ipt_udp xt_udp
#define ipt_tcp xt_tcp
#define IPT_TCP_INV_SRCPT       XT_TCP_INV_SRCPT
#define IPT_TCP_INV_DSTPT       XT_TCP_INV_DSTPT
#define IPT_TCP_INV_FLAGS       XT_TCP_INV_FLAGS
#define IPT_TCP_INV_OPTION      XT_TCP_INV_OPTION
#define IPT_TCP_INV_MASK        XT_TCP_INV_MASK
#define IPT_UDP_INV_SRCPT       XT_UDP_INV_SRCPT
#define IPT_UDP_INV_DSTPT       XT_UDP_INV_DSTPT
#define IPT_UDP_INV_MASK        XT_UDP_INV_MASK

/* Yes, Virginia, you have to zero the padding. */
struct ipt_ip {
  /* Source and destination IP addr */
  struct in_addr src, dst;
  /* Mask for src and dest IP addr */
  struct in_addr smsk, dmsk;
  char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
  unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];

  /* Protocol, 0 = ANY */
  __u16 proto;

  /* Flags word */
  __u8 flags;
  /* Inverse flags */
  __u8 invflags;
};

/* Values for "flag" field in struct ipt_ip (general ip structure). */
#define IPT_F_FRAG              0x01    /* Set if rule is a fragment rule */
#define IPT_F_GOTO              0x02    /* Set if jump is a goto */
#define IPT_F_MASK              0x03    /* All possible flag bits mask. */

/* Values for "inv" field in struct ipt_ip. */
#define IPT_INV_VIA_IN          0x01    /* Invert the sense of IN IFACE. */
#define IPT_INV_VIA_OUT         0x02    /* Invert the sense of OUT IFACE */
#define IPT_INV_TOS             0x04    /* Invert the sense of TOS. */
#define IPT_INV_SRCIP           0x08    /* Invert the sense of SRC IP. */
#define IPT_INV_DSTIP           0x10    /* Invert the sense of DST OP. */
#define IPT_INV_FRAG            0x20    /* Invert the sense of FRAG. */
#define IPT_INV_PROTO           XT_INV_PROTO
#define IPT_INV_MASK            0x7F    /* All possible flag bits mask. */

/* This structure defines each of the firewall rules.  Consists of 3
   parts which are 1) general IP header stuff 2) match specific
   stuff 3) the target to perform if the rule matches */
struct ipt_entry {
  struct ipt_ip ip;

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

/* Take a snapshot of the rules.  Returns NULL on error. */
extern struct xtc_handle *iptc_init(const char *tablename);

/* Cleanup after iptc_init(). */
extern void iptc_free(struct xtc_handle *h);

/* Iterator functions to run through the chains.  Returns NULL at end. */
extern const char *iptc_first_chain(struct xtc_handle *handle);
extern const char *iptc_next_chain(struct xtc_handle *handle);

/* Get first rule in the given chain: NULL for empty chain. */
extern const struct ipt_entry *iptc_first_rule(const char *chain,
                                        struct xtc_handle *handle);

/* Returns NULL when rules run out. */
extern const struct ipt_entry *iptc_next_rule(const struct ipt_entry *prev,
                                       struct xtc_handle *handle);

/* Returns a pointer to the target name of this entry. */
extern const char *iptc_net_target(const struct ipt_entry *e,
                            struct xtc_handle *handle);

/* Is this a built-in chain? */
extern int iptc_builtin(const char *chain, struct xtc_handle *const handle);

/* Get the policy of a given built-in chain */
extern const char *iptc_get_policy(const char *chain,
                            struct xt_counters *counter,
                            struct xtc_handle *handle);
