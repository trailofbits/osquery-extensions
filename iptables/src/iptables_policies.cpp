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

#include <boost/algorithm/string/trim.hpp>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

#include <trailofbits/extutils.h>

#include "iptables_policies.h"
#include "utils.h"

using namespace osquery;

namespace trailofbits {
osquery::TableRows IptablesPoliciesTable::generate(
    osquery::QueryContext& context) {
  osquery::TableRows results;

  for (const auto& table : getIptablesNames()) {
    genIptablesPolicy(table, results);
  }

  return results;
}

void IptablesPoliciesTable::genIptablesPolicy(const std::string& filter,
                                              osquery::TableRows& results) {
  // Initialize the access to iptc
  auto handle = iptc_init(filter.c_str());
  if (handle == nullptr) {
    return;
  }

  // Iterate through chains
  for (auto chain = iptc_first_chain(handle); chain != nullptr;
       chain = iptc_next_chain(handle)) {
    // NOTE(ww): Only built-in chains have default policies,
    // and so iptc_get_policy only works on them.
    if (!iptc_builtin(chain, handle)) {
      TLOG << "Skipping non-built-in chain: " << chain;
      continue;
    }

    Row r;
    ipt_counters counters;

    auto policy = iptc_get_policy(chain, &counters, handle);
    if (policy == nullptr) {
      TLOG << "Failed to get policy for " << filter << ":" << chain;
      continue;
    }

    r["table_name"] = TEXT(filter);
    r["chain"] = TEXT(chain);
    r["policy"] = TEXT(policy);
    r["packets"] = BIGINT(counters.pcnt);
    r["bytes"] = BIGINT(counters.bcnt);

    results.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(r))));
  }

  iptc_free(handle);
}
} // namespace trailofbits
