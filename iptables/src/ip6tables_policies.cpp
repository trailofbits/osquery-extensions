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

#include "Version.h"

#include <boost/algorithm/string/trim.hpp>

#if OSQUERY_VERSION_NUMBER < SDK_VERSION(4, 0)
#include <osquery/sdk.h>
#else
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>
#endif

#include <trailofbits/extutils.h>

#include "ip6tables_policies.h"
#include "utils.h"
#include "utils_compatible.h"

using namespace osquery;

namespace trailofbits {
osquery::TableRows Ip6tablesPoliciesTable::generate(
    osquery::QueryContext& context) {
  osquery::TableRows results;

  for (const auto& table : getIp6tablesNames()) {
    genIptablesPolicy(table, results);
  }

  return results;
}

void Ip6tablesPoliciesTable::genIptablesPolicy(const std::string& filter,
                                               osquery::TableRows& results) {
  // Initialize the access to iptc
  auto handle = ip6tc_init(filter.c_str());
  if (handle == nullptr) {
    return;
  }

  // Iterate through chains
  for (auto chain = ip6tc_first_chain(handle); chain != nullptr;
       chain = ip6tc_next_chain(handle)) {
    // NOTE(ww): Only built-in chains have default policies,
    // and so ip6tc_get_policy only works on them.
    if (!ip6tc_builtin(chain, handle)) {
      TLOG << "Skipping non-built-in chain: " << chain;
      continue;
    }

    Row r;
    ip6t_counters counters;

    auto policy = ip6tc_get_policy(chain, &counters, handle);
    if (policy == nullptr) {
      TLOG << "Failed to get policy for " << filter << ":" << chain;
      continue;
    }

    r["table_name"] = TEXT(filter);
    r["chain"] = TEXT(chain);
    r["policy"] = TEXT(policy);
    r["packets"] = BIGINT(counters.pcnt);
    r["bytes"] = BIGINT(counters.bcnt);

    insertRow(results, r);
  }

  ip6tc_free(handle);
}
} // namespace trailofbits
