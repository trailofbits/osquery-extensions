/*
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

#pragma once

#include <osquery/sdk/sdk.h>

extern "C" {
#include <libiptc/libiptc.h>
}

#include <netdb.h>
#include <sys/socket.h>

// Prepends a "!" to the given string if flag is present in the
// given struct's invert flags.
// NOTE(ww): Experimentally, it looks like recent versions of iptables
// don't use these flags much -- they only seem to get set on the protocol
// and a few other fields, with other fields receiving a mask instead.
#define FLAGNEGATE(x, flag, str)                                               \
  ((((x)->invflags) & (flag)) ? "!" + (str) : (str))

namespace trailofbits {
/* This reflects the unfortunate complexity of iptables:
 *  - A MatchMap is a mapping of strings (table names) to MatchChains
 *  - A MatchChain is a mapping of strings (chain names) to MatchLists
 *  - A MatchList is a list of MatchEntrys
 *  - A MatchEntry is a 3-tuple of match options (e.g. -m ...), target name
 * (e.g. ACCEPT), and target options
 */
using MatchEntry = std::tuple<std::string, std::string, std::string>;
using MatchList = std::vector<MatchEntry>;
using MatchChain = std::map<std::string, MatchList>;
using MatchMap = std::map<std::string, MatchChain>;

using TableList = std::vector<std::string>;

class IptablesExtBase : public osquery::TablePlugin {
 public:
  osquery::TableColumns columns() const;
  virtual osquery::TableRows generate(osquery::QueryContext& context) = 0;

 protected:
  void parseProtoMatch(const xt_entry_match* match, osquery::Row& row);

 private:
  virtual void parseTcp(const xt_entry_match* match, osquery::Row& r) = 0;
  virtual void parseUdp(const xt_entry_match* match, osquery::Row& r) = 0;
};

class IptablesPoliciesBase : public osquery::TablePlugin {
 public:
  osquery::TableColumns columns() const;
  virtual osquery::TableRows generate(osquery::QueryContext& context) = 0;

 private:
  virtual void genIptablesPolicy(const std::string& filter,
                                 osquery::TableRows& results) = 0;
};

/* Functions for parsing the output of an ip(6)tables-save command,
 * storing the results in the supplied MatchMap.
 */
osquery::Status parseIptablesSave(MatchMap& match_map);
osquery::Status parseIp6tablesSave(MatchMap& match_map);

/* Functions for returning lists of iptables tables, either IPv4 or IPv6.
 */
TableList getIptablesNames(void);
TableList getIp6tablesNames(void);

/* Functions for returning stringified IPs from various IP structures.
 */
std::string ipAsString(const sockaddr* in);
std::string ipAsString(const in_addr* in);
std::string ipAsString(const in6_addr* in);

/* Functions for returning stringified IP masks from various IP structures.
 */
std::string ipMaskAsString(const in_addr* in);
std::string ipMaskAsString(const in6_addr* in);

/* Returns a strinified interface mask for the given interface.
 */
std::string ifaceMaskAsString(const unsigned char* iface);
} // namespace trailofbits
