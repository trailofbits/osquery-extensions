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

#include <atomic>
#include <mutex>

#include <osquery/core/conversions.h>
#include <osquery/logger.h>

#include "santa.h"
#include "santarulestable.h"
#include "utils.h"

REGISTER_EXTERNAL(SantaRulesTablePlugin, "table", "santa_rules");

namespace {
const std::string kSantactlPath = "/usr/local/bin/santactl";
const std::string kMandatoryRuleDeletionError =
    "Failed to modify rules: A required rule was requested to be deleted";

using RowID = std::uint32_t;

RowID generateRowID() {
  static std::atomic_uint32_t generator(0U);
  return generator++;
}

std::string generatePrimaryKey(const std::string& shasum, bool is_certificate) {
  return shasum + "_" + (is_certificate ? "certificate" : "binary");
}

std::string generatePrimaryKey(const RuleEntry& rule) {
  auto is_certificate = (rule.type == RuleEntry::Type::Certificate);
  return generatePrimaryKey(rule.shasum, is_certificate);
}
} // namespace

struct SantaRulesTablePlugin::PrivateData final {
  std::mutex mutex;

  std::unordered_map<RowID, std::string> rowid_to_pkey;
  std::unordered_map<std::string, RuleEntry> rule_list;
};

osquery::Status SantaRulesTablePlugin::GetRowData(
    osquery::Row& row, const std::string& json_value_array) {
  row.clear();

  rapidjson::Document document;
  document.Parse(json_value_array);
  if (document.HasParseError() || !document.IsArray()) {
    return osquery::Status(1, "Invalid json received by osquery");
  }

  if (document.Size() != 3U) {
    return osquery::Status(1, "Wrong column count");
  }

  if (document[0].IsNull()) {
    return osquery::Status(1, "Missing 'shasum' value");
  }

  if (document[1].IsNull()) {
    return osquery::Status(1, "Missing 'state' value");
  }

  if (document[2].IsNull()) {
    return osquery::Status(1, "Missing 'type' value");
  }

  row["shasum"] = document[0].GetString();
  if (row["shasum"].length() != 64 ||
      std::string::npos !=
          row["shasum"].find_first_not_of("0123456789abcdef")) {
    return osquery::Status(1, "Invalid 'shasum' value");
  }

  row["state"] = document[1].GetString();
  if (row["state"] != "whitelist" && row["state"] != "blacklist") {
    return osquery::Status(1, "Invalid 'state' value");
  }

  row["type"] = document[2].GetString();
  if (row["type"] != "binary" && row["type"] != "certificate") {
    return osquery::Status(1, "Invalid 'type' value");
  }

  return osquery::Status(0, "OK");
}

SantaRulesTablePlugin::SantaRulesTablePlugin() : d(new PrivateData) {}

SantaRulesTablePlugin::~SantaRulesTablePlugin() {}

osquery::TableColumns SantaRulesTablePlugin::columns() const {
  // clang-format off
  return {
      std::make_tuple("shasum",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("state",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("type",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT)
  };
  // clang-format on
}

osquery::QueryData SantaRulesTablePlugin::generate(
    osquery::QueryContext& request) {
  std::unordered_map<RowID, std::string> rowid_to_pkey;
  std::unordered_map<std::string, RuleEntry> rule_list;

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    auto status = updateRules();
    if (!status.ok()) {
      VLOG(1) << status.getMessage();
      return {{std::make_pair("status", "failure")}};
    }

    rowid_to_pkey = d->rowid_to_pkey;
    rule_list = d->rule_list;
  }

  osquery::QueryData result;

  for (const auto& rowid_pkey_pair : rowid_to_pkey) {
    const auto& rowid = rowid_pkey_pair.first;
    const auto& pkey = rowid_pkey_pair.second;

    auto rule_it = rule_list.find(pkey);
    if (rule_it == rule_list.end()) {
      VLOG(1) << "RowID -> Primary key mismatch error in santa_rules table";
      continue;
    }

    const auto& rule = rule_it->second;

    osquery::Row row;
    row["rowid"] = std::to_string(rowid);
    row["shasum"] = rule.shasum;
    row["state"] = getRuleStateName(rule.state);
    row["type"] = getRuleTypeName(rule.type);

    result.push_back(std::move(row));
  }

  return result;
}

osquery::QueryData SantaRulesTablePlugin::insert(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  static_cast<void>(context);
  std::lock_guard<std::mutex> lock(d->mutex);

  osquery::Row row;
  auto status = GetRowData(row, request.at("json_value_array"));
  if (!status.ok()) {
    VLOG(1) << status.getMessage();
    return {{std::make_pair("status", "failure")}};
  }

  bool whitelist = row["state"] == "whitelist";
  bool certificate = row["type"] == "certificate";
  const auto& shasum = row.at("shasum");

  std::vector<std::string> santactl_args = {
      "rule", whitelist ? "--whitelist" : "--blacklist", "--sha256", shasum};

  if (certificate) {
    santactl_args.push_back("--certificate");
  }

  // The command always succeeds, even if the rule already exists; this is
  // an issue for us because we have to return a valid rowid (and we can't
  // duplicate entries)
  ProcessOutput santactl_output;
  if (!ExecuteProcess(santactl_output, kSantactlPath, santactl_args) ||
      santactl_output.exit_code != 0) {
    VLOG(1) << "Failed to add the rule";
    return {{std::make_pair("status", "failure")}};
  }

  // Enumerate the rules and search for the one we just added
  status = updateRules();
  if (!status.ok()) {
    VLOG(1) << status.getMessage();
    return {{std::make_pair("status", "failure")}};
  }

  bool rule_found = false;
  RowID row_id = 0U;
  auto primary_key = generatePrimaryKey(shasum, certificate);

  for (const auto& rowid_pkey_pair : d->rowid_to_pkey) {
    const auto& rowid = rowid_pkey_pair.first;
    const auto& pkey = rowid_pkey_pair.second;

    if (primary_key != pkey) {
      continue;
    }

    auto rule_it = d->rule_list.find(primary_key);
    if (rule_it == d->rule_list.end()) {
      VLOG(1) << "RowID -> Primary Key mismatch in the santa_rules table";
      continue;
    }

    const auto& rule = rule_it->second;
    if (rule.type != getTypeFromRuleName(row["type"].data())) {
      continue;
    }

    if (rule.state != getStateFromRuleName(row["state"].data())) {
      continue;
    }

    row_id = rowid;
    rule_found = true;

    break;
  }

  if (!rule_found) {
    return {{std::make_pair("status", "failure")}};
  }

  osquery::Row result;
  result["id"] = std::to_string(row_id);
  result["status"] = "success";
  return {result};
}

osquery::QueryData SantaRulesTablePlugin::delete_(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  static_cast<void>(context);
  std::lock_guard<std::mutex> lock(d->mutex);

  RowID rowid;

  {
    unsigned long long temp;
    auto status = osquery::safeStrtoull(request.at("id"), 10, temp);
    if (!status.ok()) {
      return {{std::make_pair("status", "failure")}};
    }

    rowid = static_cast<RowID>(temp);
  }

  auto pkey_it = d->rowid_to_pkey.find(rowid);
  if (pkey_it == d->rowid_to_pkey.end()) {
    return {{std::make_pair("status", "failure")}};
  }

  const auto& pkey = pkey_it->second;
  auto rule_it = d->rule_list.find(pkey);
  if (rule_it == d->rule_list.end()) {
    VLOG(1) << "RowID -> Primary Key mismatch in the santa_rules table";
    return {{std::make_pair("status", "failure")}};
  }

  const auto& rule = rule_it->second;
  std::vector<std::string> santactl_args = {
      "rule", "--remove", "--sha256", rule.shasum};

  if (rule.type == RuleEntry::Type::Certificate) {
    santactl_args.push_back("--certificate");
  }

  // The command always succeeds, even if the rule does not exists
  ProcessOutput santactl_output;
  if (!ExecuteProcess(santactl_output, kSantactlPath, santactl_args) ||
      santactl_output.exit_code != 0) {
    // Some rules can't be removed
    if (santactl_output.std_output.find(kMandatoryRuleDeletionError) == 0) {
      return {{std::make_pair("status", "success")}};
    }

    VLOG(1) << "Failed to remove the rule";
    return {{std::make_pair("status", "failure")}};
  }

  auto status = updateRules();
  if (!status.ok()) {
    VLOG(1) << status.getMessage();
    return {{std::make_pair("status", "failure")}};
  }

  return {{std::make_pair("status", "success")}};
}

osquery::QueryData SantaRulesTablePlugin::update(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  static_cast<void>(context);
  static_cast<void>(request);

  VLOG(1) << "UPDATE statements are not supported on the santa_rules table";
  return {{std::make_pair("status", "failure")}};
}

osquery::Status SantaRulesTablePlugin::updateRules() {
  RuleEntries new_rule_list;
  if (!collectSantaRules(new_rule_list)) {
    return osquery::Status(1, "Failed to enumerate the Santa rules");
  }

  // Add new rules, keeping the existing row ids alive
  for (const auto& new_rule : new_rule_list) {
    // clang-format off
    auto rule_it = std::find_if(
      d->rule_list.begin(),
      d->rule_list.end(),

      [new_rule](const std::pair<std::string, RuleEntry> &data) -> bool {
        const auto &old_rule = std::get<1>(data);

        return (new_rule.state == old_rule.state &&
                new_rule.type == old_rule.type &&
                new_rule.shasum == old_rule.shasum);
      }
    );
    // clang-format on

    if (rule_it != d->rule_list.end()) {
      continue;
    }

    auto new_row_id = generateRowID();
    auto primary_key = generatePrimaryKey(new_rule);

    d->rowid_to_pkey.insert({new_row_id, primary_key});
    d->rule_list.insert({primary_key, new_rule});
  }

  // Remove stale rules
  for (auto it = d->rule_list.begin(); it != d->rule_list.end();) {
    const auto& current_rule = it->second;

    // clang-format off
    auto rule_it = std::find_if(
      new_rule_list.begin(),
      new_rule_list.end(),

      [current_rule](const RuleEntry &new_rule) -> bool {
        return (new_rule.state == current_rule.state &&
                new_rule.type == current_rule.type &&
                new_rule.shasum == current_rule.shasum);
      }
    );
    // clang-format on

    if (rule_it != new_rule_list.end()) {
      it++;
      continue;
    }

    // Erase both the entry and the rowid pointer
    it = d->rule_list.erase(it);

    auto current_rule_pkey = generatePrimaryKey(current_rule);

    // clang-format off
    auto rowid_it = std::find_if(
      d->rowid_to_pkey.begin(),
      d->rowid_to_pkey.end(),

      [current_rule_pkey](const std::pair<RowID, std::string> &data) -> bool {
        const auto &pkey = std::get<1>(data);
        return current_rule_pkey == pkey;
      }
    );
    // clang-format on

    if (rowid_it != d->rowid_to_pkey.end()) {
      d->rowid_to_pkey.erase(rowid_it);
    }
  }

  return osquery::Status(0);
}
