/**
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#if OSQUERY_VERSION_NUMBER <= 4000
#include <osquery/sdk.h>
#else
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>
#endif

#include <arpa/inet.h>
#include <netdb.h>
#include <sstream>

#include <boost/algorithm/string/trim.hpp>

#include <trailofbits/extutils.h>

#include "ip6tables_ext.h"
#include "utils.h"

using namespace osquery;

namespace trailofbits {

#if OSQUERY_VERSION_NUMBER <= 4000
osquery::QueryData Ip6tablesExtTable::generate(osquery::QueryContext& context) {
  osquery::QueryData results;

  MatchMap match_map;
  auto s = parseIp6tablesSave(match_map);

  if (!s.ok()) {
    TLOG << "Error fetching matches from ip6tables-save: " << s.toString();
  }

  for (const auto& table : getIp6tablesNames()) {
    const auto& matches = match_map.find(table);

    if (matches == match_map.end()) {
      TLOG << "Couldn't associate table " << table << " with a list of matches";
      return results;
    }

    s = genIptablesRules(table, matches->second, results);

    if (!s.ok()) {
      TLOG << "Error while fetching table rules: " << s.toString();
      return results;
    }
  }

  return results;
}
#else
osquery::TableRows Ip6tablesExtTable::generate(osquery::QueryContext& context) {
  osquery::TableRows results;

  MatchMap match_map;
  auto s = parseIp6tablesSave(match_map);

  if (!s.ok()) {
    TLOG << "Error fetching matches from ip6tables-save: " << s.toString();
  }

  for (const auto& table : getIp6tablesNames()) {
    const auto& matches = match_map.find(table);

    if (matches == match_map.end()) {
      TLOG << "Couldn't associate table " << table << " with a list of matches";
      return results;
    }

    s = genIptablesRules(table, matches->second, results);

    if (!s.ok()) {
      TLOG << "Error while fetching table rules: " << s.toString();
      return results;
    }
  }

  return results;
}
#endif

osquery::Status Ip6tablesExtTable::genIptablesRules(
    const std::string& filter,
    const MatchChain& matches,
#if OSQUERY_VERSION_NUMBER <= 4000
    osquery::QueryData& results
#else
    osquery::TableRows& results
#endif
    ) {
  // Initialize the access to ip6tc
  auto handle = ip6tc_init(filter.c_str());
  if (handle == nullptr) {
    return osquery::Status(1, "Couldn't initialize ip6tables handle");
  }

  // Iterate through chains
  for (auto chain = ip6tc_first_chain(handle); chain != nullptr;
       chain = ip6tc_next_chain(handle)) {
    // NOTE(ww): Rules are 1-based in libip6tc, as evidenced by
    // ip6tc_read_counter.
    unsigned long ruleno = 1;
    const auto& match_pair = matches.find(chain);

    if (match_pair == matches.end()) {
      TLOG << "couldn't associate " << chain << " with a list of matches";
      return osquery::Status(1, "couldn't associate chain with a match list!");
    }

    const auto& match_list = match_pair->second;

    // Iterating through all the rules per chain
    for (auto chain_rule = ip6tc_first_rule(chain, handle);
         chain_rule != nullptr;
         chain_rule = ip6tc_next_rule(chain_rule, handle)) {
      osquery::Row r;

      r["table_name"] = TEXT(filter);
      r["chain"] = TEXT(chain);
      r["packets"] = BIGINT(chain_rule->counters.pcnt);
      r["bytes"] = BIGINT(chain_rule->counters.bcnt);
      r["ruleno"] = INTEGER(ruleno);

      if (ruleno - 1 < match_list.size()) {
        const auto& match_entry = match_list.at(ruleno - 1);

        r["match"] = TEXT(std::get<0>(match_entry));
        r["target"] = TEXT(std::get<1>(match_entry));
        r["target_options"] = TEXT(std::get<2>(match_entry));
      } else {
        TLOG << "rule number mismatch: " << (ruleno - 1)
             << " >= " << match_list.size();
        r["match"] = TEXT("");
        r["target"] = TEXT("");
        r["target_options"] = TEXT("");
      }

      if (chain_rule->target_offset) {
        // This is basically the IP6T_MATCH_ITERATE macro from ip6tables,
        // but without the GNU C magic (void pointer arithmetic,
        // macro expression extensions).
        const xt_entry_match* match;
        for (int i = sizeof(ip6t_entry); i < chain_rule->target_offset;
             i += match->u.match_size) {
          match = reinterpret_cast<const xt_entry_match*>(
              reinterpret_cast<const char*>(chain_rule) + i);
          parseProtoMatch(match, r);
        }
      } else {
        r["src_port"] = TEXT("");
        r["dst_port"] = TEXT("");
      }

      parseIpEntry(&chain_rule->ipv6, r);
#if OSQUERY_VERSION_NUMBER <= 4000
      results.push_back(r);
#else
      results.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(r))));
#endif
      ruleno++;
    } // Rule iteration
  } // Chain iteration

  ip6tc_free(handle);

  return osquery::Status(0);
}

void Ip6tablesExtTable::parseTcp(const xt_entry_match* match, osquery::Row& r) {
  auto tcp = reinterpret_cast<const ip6t_tcp*>(match->data);

  std::string src_port =
      std::to_string(tcp->spts[0]) + ':' + std::to_string(tcp->spts[1]);
  r["src_port"] = FLAGNEGATE(tcp, IP6T_TCP_INV_SRCPT, src_port);

  std::string dst_port =
      std::to_string(tcp->dpts[0]) + ':' + std::to_string(tcp->dpts[1]);
  r["dst_port"] = FLAGNEGATE(tcp, IP6T_TCP_INV_DSTPT, dst_port);
}

void Ip6tablesExtTable::parseUdp(const xt_entry_match* match, osquery::Row& r) {
  auto udp = reinterpret_cast<const ip6t_udp*>(match->data);

  std::string src_port =
      std::to_string(udp->spts[0]) + ':' + std::to_string(udp->spts[1]);
  r["src_port"] = FLAGNEGATE(udp, IP6T_UDP_INV_SRCPT, src_port);

  std::string dst_port =
      std::to_string(udp->dpts[0]) + ':' + std::to_string(udp->dpts[1]);
  r["dst_port"] = FLAGNEGATE(udp, IP6T_UDP_INV_DSTPT, dst_port);
}

void Ip6tablesExtTable::parseIpEntry(const ip6t_ip6* ip, osquery::Row& r) {
  protoent* pent = getprotobynumber(ip->proto);

  std::string protocol;
  if (pent) {
    protocol = TEXT(pent->p_name);
  } else {
    protocol = TEXT(ip->proto);
  }
  r["protocol"] = FLAGNEGATE(ip, IP6T_INV_PROTO, protocol);

  std::string iniface;
  if (strlen(ip->iniface)) {
    iniface = FLAGNEGATE(ip, IP6T_INV_VIA_IN, TEXT(ip->iniface));
  } else if (ip->invflags & IP6T_INV_VIA_IN) {
    // NOTE(ww): This shouldn't be possible via the `ip6tables` CLI,
    // but who knows?
    iniface = "none";
  } else {
    iniface = "all";
  }
  r["iniface"] = TEXT(iniface);

  std::string outiface;
  if (strlen(ip->outiface)) {
    outiface = FLAGNEGATE(ip, IP6T_INV_VIA_OUT, TEXT(ip->outiface));
  } else if (ip->invflags & IP6T_INV_VIA_OUT) {
    // NOTE(ww): This shouldn't be possible via the `ip6tables` CLI,
    // but who knows?
    outiface = "none";
  } else {
    outiface = "all";
  }
  r["outiface"] = TEXT(outiface);

  r["src_ip"] = FLAGNEGATE(ip, IP6T_INV_SRCIP, ipAsString(&ip->src));
  r["dst_ip"] = FLAGNEGATE(ip, IP6T_INV_DSTIP, ipAsString(&ip->dst));
  r["src_mask"] = ipMaskAsString(&ip->smsk);
  r["dst_mask"] = ipMaskAsString(&ip->dmsk);
  r["iniface_mask"] = TEXT(ifaceMaskAsString(ip->iniface_mask));
  r["outiface_mask"] = TEXT(ifaceMaskAsString(ip->outiface_mask));
}

} // namespace trailofbits
