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
 *
 *  Parts of this file are also:
 *
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/sdk/sdk.h>
#include <osquery/filesystem/filesystem.h>

#include <net/if.h>
#include <netdb.h>
#include <string>
#include <sys/socket.h>

#include <boost/algorithm/string/trim.hpp>

#include <trailofbits/extutils.h>

#include "utils.h"

using namespace osquery;

namespace trailofbits {
static const std::string kIptablesSave = "/sbin/iptables-save";
static const std::string kIp6tablesSave = "/sbin/ip6tables-save";

static const std::string kIptablesNamesFile = "/proc/net/ip_tables_names";
static const std::string kIp6tablesNamesFile = "/proc/net/ip6_tables_names";

static const std::string kHexMap = "0123456789ABCDEF";

static const int kMaskHighBits = 4;
static const int kMaskLowBits = 15;

static TableList getTableNames(const std::string& filename) {
  std::string content;

  auto s = readFile(filename, content);

  if (!s.ok()) {
    TLOG << "Error reading: " << filename << ": " << s.toString();
    return {};
  }

  auto results = SplitString(content, '\n');

  for (auto& result : results) {
    boost::algorithm::trim(result);
  }

  return results;
}

/* NOTE(ww): This function takes either iptables-save or ip6tables-save.
 * It would be nice to use iptables-xml and ip6tables-xml, but ip6tables-xml
 * doesn't exist yet and iptables-xml frequently hangs (during experimentation).
 */
Status genMatchMap(const std::string& ipt_cmd, MatchMap& match_map) {
  ProcessOutput output;

  if (!ExecuteProcess(output, ipt_cmd, {}) || output.exit_code != 0) {
    return Status(1, "couldn't exec " + ipt_cmd);
  }

  if (output.std_output.empty()) {
    return Status(1, "no output from command");
  }

  std::string table;
  std::string chain;
  for (const auto& line : SplitString(output.std_output, '\n')) {
    std::string match;
    std::string target;
    std::string target_options;

    // If the line is empty or a comment, skip it.
    if (line.empty() || line.at(0) == '#') {
      continue;
    }

    // If the line is a filter name, record it and prep our toplevel map with
    // it.
    if (line.at(0) == '*') {
      table = line.substr(1);
      match_map[table];
      continue;
    }

    // If the line is a chain name, record it and prep our chain map with it.
    if (line.at(0) == ':') {
      auto stop = line.find(" ");
      chain = line.substr(1, stop - 1);
      match_map[table][chain];
      continue;
    }

    // If the line is a rule, look for match entries, targets,
    // and target options within it.
    if (line.find("-A") == 0) {
      auto start = line.find(" ");
      auto stop = line.find(" ", start + 1);

      chain = line.substr(start + 1, stop - start - 1);

      // Matches begin with an -m.
      start = line.find(" -m ");

      // Targets begin with a -j or a -g.
      stop = line.rfind(" -j ");
      if (stop == std::string::npos) {
        stop = line.rfind(" -g ");
      }

      // Match extraction.
      if (start == std::string::npos) {
        match = "";
      } else {
        if (stop != std::string::npos && stop < start) {
          TLOG << "Oddity: -j or -g before -m: " << line;
          match = "";
        } else {
          match = line.substr(start + 1, stop - start - 1);
        }
      }

      // Target extraction.
      if (stop == std::string::npos) {
        target = "";
      } else {
        start = stop;
        start = line.find(" ", start + 1);
        stop = line.find(" ", start + 1);

        target = line.substr(start + 1, stop - start - 1);
      }

      // Target option extraction.
      if (stop == std::string::npos) {
        target_options = "";
      } else {
        start = stop;
        target_options = line.substr(start + 1);
      }

      match_map[table][chain].push_back(
          std::make_tuple(match, target, target_options));
    }
  }

  return Status(0);
}

TableColumns IptablesExtBase::columns() const {
  return {
      std::make_tuple("table_name", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("chain", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("ruleno", INTEGER_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("target", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("target_options", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("match", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("protocol", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("src_port", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("dst_port", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("src_ip", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("src_mask", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("iniface", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("iniface_mask", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("dst_ip", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("dst_mask", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("outiface", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("outiface_mask", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("packets", BIGINT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("bytes", BIGINT_TYPE, ColumnOptions::DEFAULT),
  };
}

void IptablesExtBase::parseProtoMatch(const xt_entry_match* match, Row& row) {
  std::string match_name(match->u.user.name);

  // NOTE(ww): ICMP can also appear here, but there's no point in handling
  // it -- it doesn't have any ports to parse.
  if (match_name == "tcp") {
    parseTcp(match, row);
  } else if (match_name == "udp") {
    parseUdp(match, row);
  }
}

TableColumns IptablesPoliciesBase::columns() const {
  return {
      std::make_tuple("table_name", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("chain", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("policy", TEXT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("packets", BIGINT_TYPE, ColumnOptions::DEFAULT),
      std::make_tuple("bytes", BIGINT_TYPE, ColumnOptions::DEFAULT),
  };
}

Status parseIptablesSave(MatchMap& match_map) {
  return genMatchMap(kIptablesSave, match_map);
}

Status parseIp6tablesSave(MatchMap& match_map) {
  return genMatchMap(kIp6tablesSave, match_map);
}

TableList getIptablesNames(void) {
  return getTableNames(kIptablesNamesFile);
}

TableList getIp6tablesNames(void) {
  return getTableNames(kIp6tablesNamesFile);
}

std::string ipAsString(const sockaddr* in) {
  char dst[INET6_ADDRSTRLEN] = {0};

  socklen_t addrlen =
      in->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
  if (getnameinfo(in, addrlen, dst, sizeof(dst), nullptr, 0, NI_NUMERICHOST) !=
      0) {
    return "";
  }

  std::string address(dst);
  boost::algorithm::trim(address);
  return address;
}

std::string ipAsString(const in_addr* in) {
  sockaddr_in addr;
  addr.sin_addr = *in;
  addr.sin_family = AF_INET;
  addr.sin_port = 0;

  return ipAsString(reinterpret_cast<sockaddr*>(&addr));
}

std::string ipAsString(const in6_addr* in) {
  sockaddr_in6 addr;
  addr.sin6_addr = *in;
  addr.sin6_family = AF_INET6;
  addr.sin6_port = 0;
  addr.sin6_scope_id = 0;

  return ipAsString(reinterpret_cast<sockaddr*>(&addr));
}

std::string ipMaskAsString(const in_addr* in) {
  return ipAsString(in);
}

std::string ipMaskAsString(const in6_addr* in) {
  std::string mask_str = "";
  char aux_char[2] = {0};
  unsigned int ncol = 0;

  for (int i = 0; i < 16; i++) {
    aux_char[0] = kHexMap[in->s6_addr[i] >> kMaskHighBits];
    aux_char[1] = kHexMap[in->s6_addr[i] & kMaskLowBits];
    mask_str += aux_char[0];
    mask_str += aux_char[1];

    if ((mask_str.size() - ncol) % 4 == 0) {
      mask_str += ":";
      ncol++;
    }
  }

  if (mask_str.back() == ':') {
    mask_str.pop_back();
  }

  return mask_str;
}

std::string ifaceMaskAsString(const unsigned char* iface) {
  std::string iface_str = "";
  char aux_char[2] = {0};

  for (int i = 0; i < IFNAMSIZ && iface[i] != 0x00; i++) {
    aux_char[0] = kHexMap[iface[i] >> kMaskHighBits];
    aux_char[1] = kHexMap[iface[i] & kMaskLowBits];
    iface_str += aux_char[0];
    iface_str += aux_char[1];
  }
  return iface_str;
}

} // namespace trailofbits
