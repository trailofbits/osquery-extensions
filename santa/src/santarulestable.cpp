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

#include "santarulestable.h"

#include <atomic>
#include <mutex>

#include <osquery/logger/logger.h>
#include <osquery/sql/dynamic_table_row.h>

#include "santa.h"
#include "utils.h"

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

  if (document.Size() != 4U) {
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

  // The custom_message column is optional, and may be null.
  if (document[3].IsNull()) {
    row["custom_message"] = "";
  } else {
    // It can also be any string.
    row["custom_message"] = document[3].GetString();
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
                      osquery::ColumnOptions::DEFAULT),
      
      std::make_tuple("custom_message",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT)
  };
  // clang-format on
}

osquery::TableRows SantaRulesTablePlugin::generate(
    osquery::QueryContext& request) {
  std::unordered_map<RowID, std::string> rowid_to_pkey;
  std::unordered_map<std::string, RuleEntry> rule_list;
  osquery::TableRows result;

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    auto status = updateRules();
    if (!status.ok()) {
      VLOG(1) << status.getMessage();
      osquery::DynamicTableRowHolder row;
      row["status"] = "failure";
      result.emplace_back(row);
      return result;
    }

    rowid_to_pkey = d->rowid_to_pkey;
    rule_list = d->rule_list;
  }

  for (const auto& rowid_pkey_pair : rowid_to_pkey) {
    const auto& rowid = rowid_pkey_pair.first;
    const auto& pkey = rowid_pkey_pair.second;

    auto rule_it = rule_list.find(pkey);
    if (rule_it == rule_list.end()) {
      VLOG(1) << "RowID -> Primary key mismatch error in santa_rules table";
      continue;
    }

    const auto& rule = rule_it->second;

    osquery::DynamicTableRowHolder row;
    row["rowid"] = std::to_string(rowid);
    row["shasum"] = rule.shasum;
    row["state"] = getRuleStateName(rule.state);
    row["type"] = getRuleTypeName(rule.type);
    row["custom_message"] = rule.custom_message;

    result.emplace_back(row);
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
  const auto& custom_message = row.at("custom_message");

  std::vector<std::string> santactl_args = {
      "rule",
      whitelist ? "--whitelist" : "--blacklist",
      "--sha256",
      shasum,
      "--message",
      custom_message};

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

    // Note: rule.custom_message field is not matched.

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
    char* null_term_ptr = nullptr;
    auto temp = std::strtoull(request.at("id").c_str(), &null_term_ptr, 10);
    if (*null_term_ptr != 0) {
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

  // The santactl command always succeeds, even if the rule does not exist.
  ProcessOutput santactl_output;
  if (!ExecuteProcess(santactl_output, kSantactlPath, santactl_args) ||
      santactl_output.exit_code != 0) {
    // Some rules can't be removed.
    if (santactl_output.std_output.find(kMandatoryRuleDeletionError) == 0) {
      VLOG(1) << "Rule "
              << rule.shasum + "/" + getRuleTypeName(rule.type) +
                     " is mandatory and can't be removed";
    } else {
      VLOG(1) << "Failed to remove the rule";
    }

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

  auto old_rowid_mappings = std::move(d->rowid_to_pkey);
  d->rowid_to_pkey.clear();

  d->rule_list.clear();

  for (const auto& new_rule : new_rule_list) {
    auto primary_key = generatePrimaryKey(new_rule);
    d->rule_list.insert({primary_key, new_rule});

    RowID rowid;

    {
      // clang-format off
      auto it = std::find_if(
        old_rowid_mappings.begin(),
        old_rowid_mappings.end(),

        [primary_key](const std::pair<RowID, std::string> &pkey_rowid_pair) -> bool {
          return (primary_key == pkey_rowid_pair.second);
        }
      );
      // clang-format on

      if (it == old_rowid_mappings.end()) {
        rowid = generateRowID();
      } else {
        rowid = it->first;
      }
    }

    d->rowid_to_pkey.insert({rowid, primary_key});
  }

  return osquery::Status(0);
}
