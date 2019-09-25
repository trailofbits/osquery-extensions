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

#include "hostblacklist.h"
#include "globals.h"

#include <trailofbits/ihostsfile.h>

#if OSQUERY_VERSION_NUMBER <= 4000
#include <osquery/core/conversions.h>
#else
#include <osquery/sql/dynamic_table_row.h>
#endif

#include <osquery/logger.h>
#include <osquery/system.h>


#include <algorithm>
#include <iostream>
#include <mutex>

#include <boost/algorithm/string.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/regex.hpp>
#include <boost/serialization/unordered_map.hpp>

namespace b_asio = boost::asio;
namespace b_ip = boost::asio::ip;
namespace b_fs = boost::filesystem;
namespace b_arc = boost::archive;

namespace boost {
namespace serialization {
template <class Archive>
void serialize(Archive& archive,
               trailofbits::HostRule& rule,
               const unsigned int version) {
  static_cast<void>(version);

  archive& rule.address;
  archive& rule.domain;
  archive& rule.sinkhole;
}
} // namespace serialization
} // namespace boost

namespace {
bool ValidateIPAddress(const std::string& ip_address) {
  boost::regex expression(
      "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-"
      "9]|[01]?[0-9][0-9]?)$");
  return boost::regex_match(ip_address, expression);
}
} // namespace

namespace trailofbits {
struct HostBlacklistTable::PrivateData final {
  std::mutex mutex;

  std::unique_ptr<IHostsFile> hosts_file;

  HostRuleMap data;
  RowIdToPrimaryKeyMap row_id_to_pkey;

  b_fs::path configuration_file_path;
};

HostBlacklistTable::HostBlacklistTable() : d(new PrivateData) {
  try {
    auto status = CreateHostsFileObject(d->hosts_file);
    if (!status.success()) {
      throw std::runtime_error("Initialization error");
    }

    d->configuration_file_path = CONFIGURATION_ROOT;
    d->configuration_file_path /= "hostblacklist.cfg";

    loadConfiguration();

  } catch (const std::bad_alloc&) {
    throw std::runtime_error("Memory allocation error");
  }
}

HostBlacklistTable::~HostBlacklistTable() {}

osquery::TableColumns HostBlacklistTable::columns() const {
  // clang-format off
  return {
    std::make_tuple("address", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("domain", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("sinkhole", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("firewall_block", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("dns_block", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),

    std::make_tuple("address_type", osquery::TEXT_TYPE, osquery::ColumnOptions::HIDDEN)
  };
  // clang-format on
}

#if OSQUERY_VERSION_NUMBER <= 4000
osquery::QueryData HostBlacklistTable::generate(
    osquery::QueryContext& context) {
  static_cast<void>(context);

  HostRuleMap table_data;
  RowIdToPrimaryKeyMap table_row_id_to_pkey;

  std::set<std::string> firewall_blacklist;
  std::unordered_map<std::string, std::string> hosts_file;

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    table_data = d->data;
    table_row_id_to_pkey = d->row_id_to_pkey;

    // clang-format off
    auto fw_status = GetFirewall().enumerateBlacklistedHosts(
      [](const std::string &host, void* user_defined) -> bool {

        auto &blacklist =
          *static_cast<std::set<std::string>*>(user_defined);

        blacklist.insert(host);

        return true;
      },

      &firewall_blacklist
    );

    auto hosts_status = d->hosts_file->enumerateHosts(
      [](const std::string &domain, const std::string &address, void *user_defined) -> bool {

        auto &hosts =
          *static_cast<std::unordered_map<std::string, std::string>*>(user_defined);

        hosts.insert({domain, address});
        return true;
      },

      &hosts_file
    );
    // clang-format on

    static_cast<void>(fw_status);
    static_cast<void>(hosts_status);
  }

  osquery::QueryData results;

  // Add managed firewall and dns rules
  for (const auto& pair : table_row_id_to_pkey) {
    const auto& row_id = pair.first;
    const auto& pkey = pair.second;
    const auto& rule = table_data.at(pkey);

    osquery::Row row;
    row["rowid"] = std::to_string(row_id);

    // This is only used when inserting data; set as null
    row["address_type"] = "";

    row["address"] = rule.address;
    row["domain"] = rule.domain;
    row["sinkhole"] = rule.sinkhole;

    auto fw_blacklist_it = firewall_blacklist.find(rule.address);
    if (fw_blacklist_it != firewall_blacklist.end()) {
      firewall_blacklist.erase(fw_blacklist_it);
      row["firewall_block"] = "ENABLED";
    } else {
      row["firewall_block"] = "DISABLED";
    }

    auto hosts_file_entry_it = hosts_file.find(rule.domain);
    if (hosts_file_entry_it == hosts_file.end()) {
      row["dns_block"] = "DISABLED";
    } else if (hosts_file_entry_it->second != rule.sinkhole) {
      hosts_file.erase(hosts_file_entry_it);
      row["dns_block"] = "ALTERED";
    } else {
      hosts_file.erase(hosts_file_entry_it);
      row["dns_block"] = "ENABLED";
    }

    results.push_back(row);
  }

  // Add unmanaged firewall rules
  RowID temp_row_id = 0x80000000ULL;
  for (const auto& host : firewall_blacklist) {
    osquery::Row row;
    row["rowid"] = std::to_string(temp_row_id);
    row["address_type"] =
        ""; // This is only used when inserting data; set as null
    row["address"] = host;
    row["domain"] = "";
    row["sinkhole"] = "";
    row["firewall_block"] = "UNMANAGED";
    row["dns_block"] = "";

    results.push_back(row);
    temp_row_id++;
  }

  // Add unmanaged host entries
  for (const auto& pair : hosts_file) {
    const auto& domain = pair.first;
    const auto& address = pair.second;

    osquery::Row row;
    row["rowid"] = std::to_string(temp_row_id);
    row["address_type"] =
        ""; // This is only used when inserting data; set as null
    row["address"] = "";
    row["domain"] = domain;
    row["sinkhole"] = address;
    row["firewall_block"] = "";
    row["dns_block"] = "UNMANAGED";

    results.push_back(row);
    temp_row_id++;
  }

  return results;
}
#else
osquery::TableRows HostBlacklistTable::generate(
    osquery::QueryContext& context) {
  static_cast<void>(context);

  HostRuleMap table_data;
  RowIdToPrimaryKeyMap table_row_id_to_pkey;

  std::set<std::string> firewall_blacklist;
  std::unordered_map<std::string, std::string> hosts_file;

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    table_data = d->data;
    table_row_id_to_pkey = d->row_id_to_pkey;

    // clang-format off
    auto fw_status = GetFirewall().enumerateBlacklistedHosts(
      [](const std::string &host, void* user_defined) -> bool {

        auto &blacklist =
          *static_cast<std::set<std::string>*>(user_defined);

        blacklist.insert(host);

        return true;
      },

      &firewall_blacklist
    );

    auto hosts_status = d->hosts_file->enumerateHosts(
      [](const std::string &domain, const std::string &address, void *user_defined) -> bool {

        auto &hosts =
          *static_cast<std::unordered_map<std::string, std::string>*>(user_defined);

        hosts.insert({domain, address});
        return true;
      },

      &hosts_file
    );
    // clang-format on

    static_cast<void>(fw_status);
    static_cast<void>(hosts_status);
  }

  osquery::TableRows results;

  // Add managed firewall and dns rules
  for (const auto& pair : table_row_id_to_pkey) {
    const auto& row_id = pair.first;
    const auto& pkey = pair.second;
    const auto& rule = table_data.at(pkey);

    osquery::Row row;
    row["rowid"] = std::to_string(row_id);

    // This is only used when inserting data; set as null
    row["address_type"] = "";

    row["address"] = rule.address;
    row["domain"] = rule.domain;
    row["sinkhole"] = rule.sinkhole;

    auto fw_blacklist_it = firewall_blacklist.find(rule.address);
    if (fw_blacklist_it != firewall_blacklist.end()) {
      firewall_blacklist.erase(fw_blacklist_it);
      row["firewall_block"] = "ENABLED";
    } else {
      row["firewall_block"] = "DISABLED";
    }

    auto hosts_file_entry_it = hosts_file.find(rule.domain);
    if (hosts_file_entry_it == hosts_file.end()) {
      row["dns_block"] = "DISABLED";
    } else if (hosts_file_entry_it->second != rule.sinkhole) {
      hosts_file.erase(hosts_file_entry_it);
      row["dns_block"] = "ALTERED";
    } else {
      hosts_file.erase(hosts_file_entry_it);
      row["dns_block"] = "ENABLED";
    }

    results.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(row))));
  }

  // Add unmanaged firewall rules
  RowID temp_row_id = 0x80000000ULL;
  for (const auto& host : firewall_blacklist) {
    osquery::Row row;
    row["rowid"] = std::to_string(temp_row_id);
    row["address_type"] =
        ""; // This is only used when inserting data; set as null
    row["address"] = host;
    row["domain"] = "";
    row["sinkhole"] = "";
    row["firewall_block"] = "UNMANAGED";
    row["dns_block"] = "";

    results.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(row))));
    temp_row_id++;
  }

  // Add unmanaged host entries
  for (const auto& pair : hosts_file) {
    const auto& domain = pair.first;
    const auto& address = pair.second;

    osquery::Row row;
    row["rowid"] = std::to_string(temp_row_id);
    row["address_type"] =
        ""; // This is only used when inserting data; set as null
    row["address"] = "";
    row["domain"] = domain;
    row["sinkhole"] = address;
    row["firewall_block"] = "";
    row["dns_block"] = "UNMANAGED";

    results.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(row))));
    temp_row_id++;
  }

  return results;
}
#endif

osquery::QueryData HostBlacklistTable::insert(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  static_cast<void>(context);

  if (request.at("auto_rowid") != "false") {
    VLOG(1) << "Unsupported statement with auto_rowid enabled";
    return {{std::make_pair("status", "failure")}};
  }

  osquery::Row row;
  auto status = GetRowData(row, request.at("json_value_array"));
  if (!status.ok()) {
    VLOG(1) << status.getMessage();
    return {{std::make_pair("status", "failure")}};
  }

  bool domain_resolution =
      row.at("address").empty() && !row.at("domain").empty();
  status = PrepareInsertData(row);
  if (!status.ok()) {
    VLOG(1) << status.getMessage();
    return {{std::make_pair("status", "failure")}};
  }

  if (!IsInsertDataValid(row)) {
    std::stringstream temp;
    temp << "Invalid insert data: ";
    for (const auto& pair : row) {
      temp << pair.first << "=\"" << pair.second << "\" ";
    }

    VLOG(1) << temp.str();
    return {{std::make_pair("status", "failure")}};
  }

  HostRule rule;
  rule.address = row["address"];
  rule.domain = row["domain"];
  rule.sinkhole = row["sinkhole"];

  auto primary_key = GeneratePrimaryKey(rule);

  std::lock_guard<std::mutex> lock(d->mutex);

  // Make sure we never generate constraint errors
  if (d->data.find(primary_key) != d->data.end()) {
    // clang-format off
    auto row_id_to_pkey_it = std::find_if(
      d->row_id_to_pkey.begin(),
      d->row_id_to_pkey.end(),

      [primary_key](const std::pair<RowID, std::string> &pair) -> bool {
        return (primary_key == std::get<1>(pair));
      }
    );
    // clang-format on

    if (row_id_to_pkey_it != d->row_id_to_pkey.end()) {
      osquery::Row result;
      result["id"] = std::to_string(row_id_to_pkey_it->first);
      result["status"] = "success";
      return {result};

    } else {
      d->data.erase(primary_key);
    }
  }

  // Fail INSERTs that involve name resolution for domains that are present
  // into our /etc/hosts files; we don't want to block our sinkhole hosts
  // by mistake!
  struct CallbackData final {
    std::string domain;
    bool hosts_file_present;
  };

  CallbackData callback_data = {row.at("domain"), false};

  // clang-format off
  auto hosts_status = d->hosts_file->enumerateHosts(
    [](const std::string &domain, const std::string &address, void *user_defined) -> bool {
      static_cast<void>(address);

      auto &cb_data = *static_cast<CallbackData *>(user_defined);

      if (cb_data.domain == domain) {
        cb_data.hosts_file_present = true;
        return false;
      }

      return true;
    },

    &callback_data
  );
  // clang-format on

  if (!hosts_status.success()) {
    return {{std::make_pair("status", "failure")}};
  }

  if (domain_resolution && callback_data.hosts_file_present) {
    VLOG(1) << "The following domain is present in the /etc/hosts file and "
               "will not be accepted without an explicit address: "
            << row["domain"];

    return {{std::make_pair("status", "failure")}};
  }

  auto row_id = GenerateRowID();
  d->data.insert({primary_key, rule});
  d->row_id_to_pkey.insert({row_id, primary_key});

  // Multiple domains may point to the same address
  auto fw_status = GetFirewall().addHostToBlacklist(rule.address);
  if (!fw_status.success() &&
      fw_status.detail() != IFirewall::Detail::AlreadyExists) {
    VLOG(1) << "Failed to enable the firewall host rule";
  }

  hosts_status = d->hosts_file->addHost(rule.domain, rule.sinkhole);
  if (!hosts_status.success() &&
      hosts_status.detail() != IHostsFile::Detail::AlreadyExists) {
    VLOG(1) << "Failed to enable the hosts file rule";
  }

  saveConfiguration();

  osquery::Row result;
  result["id"] = std::to_string(row_id);
  result["status"] = "success";
  return {result};
}

osquery::QueryData HostBlacklistTable::delete_(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  static_cast<void>(context);

  char* null_term_ptr = nullptr;
  auto row_id = std::strtoull(request.at("id").c_str(), &null_term_ptr, 10);
  if (*null_term_ptr != 0) {
    return {{std::make_pair("status", "failure")}};
  }

  if ((row_id & 0x80000000U) != 0) {
    return {{std::make_pair("status", "failure")}};
  }

  std::lock_guard<std::mutex> lock(d->mutex);

  auto row_id_to_pkey_it = d->row_id_to_pkey.find(row_id);
  if (row_id_to_pkey_it == d->row_id_to_pkey.end()) {
    return {{std::make_pair("status", "failure")}};
  }

  auto primary_key = row_id_to_pkey_it->second;
  d->row_id_to_pkey.erase(row_id_to_pkey_it);

  auto rule_it = d->data.find(primary_key);
  if (rule_it == d->data.end()) {
    return {{std::make_pair("status", "failure")}};
  }

  auto rule = rule_it->second;
  d->data.erase(rule_it);
  saveConfiguration();

  auto fw_status = GetFirewall().removeHostFromBlacklist(rule.address);
  if (!fw_status.success() &&
      fw_status.detail() != IFirewall::Detail::NotFound) {
    VLOG(1) << "Failed to remove the firewall host rule";
  }

  auto hosts_status = d->hosts_file->removeHost(rule.domain);
  if (!hosts_status.success() &&
      hosts_status.detail() != IHostsFile::Detail::NotFound) {
    VLOG(1) << "Failed to remove the hosts file rule";
  }

  return {{std::make_pair("status", "success")}};
}

osquery::QueryData HostBlacklistTable::update(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  static_cast<void>(context);

  char* null_term_ptr = nullptr;
  auto row_id = std::strtoull(request.at("id").c_str(), &null_term_ptr, 10);
  if (*null_term_ptr != 0) {
    return {{std::make_pair("status", "failure")}};
  }

  if ((row_id & 0x80000000U) != 0) {
    return {{std::make_pair("status", "failure")}};
  }

  osquery::Row row;
  auto status = GetRowData(row, request.at("json_value_array"));
  if (!status.ok()) {
    VLOG(1) << status.getMessage();
    return {{std::make_pair("status", "failure")}};
  }

  status = PrepareInsertData(row);
  if (!status.ok()) {
    VLOG(1) << status.getMessage();
    return {{std::make_pair("status", "failure")}};
  }

  if (!IsInsertDataValid(row)) {
    std::stringstream temp;
    temp << "Invalid insert data: ";
    for (const auto& pair : row) {
      temp << pair.first << "=\"" << pair.second << "\" ";
    }

    VLOG(1) << temp.str();
    return {{std::make_pair("status", "failure")}};
  }

  HostRule new_rule;
  new_rule.address = row["address"];
  new_rule.domain = row["domain"];
  new_rule.sinkhole = row["sinkhole"];

  auto new_primary_key = GeneratePrimaryKey(new_rule);

  std::lock_guard<std::mutex> lock(d->mutex);

  auto row_id_to_pkey_it = d->row_id_to_pkey.find(row_id);
  if (row_id_to_pkey_it == d->row_id_to_pkey.end()) {
    return {{std::make_pair("status", "failure")}};
  }

  auto original_primary_key = row_id_to_pkey_it->second;
  if (original_primary_key == new_primary_key) {
    return {{std::make_pair("status", "success")}};
  }

  if (d->data.find(new_primary_key) != d->data.end()) {
    return {{std::make_pair("status", "constraint")}};
  }

  auto original_rule_it = d->data.find(original_primary_key);
  if (original_rule_it == d->data.end()) {
    return {{std::make_pair("status", "failure")}};
  }

  auto original_rule = original_rule_it->second;

  d->row_id_to_pkey.erase(row_id_to_pkey_it);
  d->data.erase(original_rule_it);

  auto fw_status = GetFirewall().removeHostFromBlacklist(original_rule.address);
  if (!fw_status.success()) {
    VLOG(1) << "Failed to remove the firewall host rule";
  }

  auto hosts_status = d->hosts_file->removeHost(original_rule.domain);
  if (!hosts_status.success() &&
      hosts_status.detail() != IHostsFile::Detail::NotFound) {
    VLOG(1) << "Failed to remove the hosts file rule";
  }

  RowID new_row_id;
  auto new_row_id_it = request.find("new_id");
  if (new_row_id_it != request.end()) {
    // sqlite has generated the new rowid for us, so we'll discard
    // the one we have
    const auto& new_id_string = new_row_id_it->second;

    null_term_ptr = nullptr;
    auto temp = std::strtoull(new_id_string.c_str(), &null_term_ptr, 10);
    if (*null_term_ptr != 0) {
      return {{std::make_pair("status", "failure")}};
    }

    new_row_id = static_cast<RowID>(temp);

  } else {
    // Here we are supposed to keep the rowid we already have
    new_row_id = row_id;
  }

  d->data.insert({new_primary_key, new_rule});
  d->row_id_to_pkey.insert({new_row_id, new_primary_key});
  saveConfiguration();

  fw_status = GetFirewall().addHostToBlacklist(new_rule.address);
  if (!fw_status.success()) {
    VLOG(1) << "Failed to add the firewall host rule";
  }

  hosts_status = d->hosts_file->addHost(new_rule.domain, new_rule.sinkhole);
  if (!hosts_status.success() &&
      hosts_status.detail() != IHostsFile::Detail::AlreadyExists) {
    VLOG(1) << "Failed to enable the hosts file rule";
  }

  return {{std::make_pair("status", "success")}};
}

osquery::Status HostBlacklistTable::GetRowData(
    osquery::Row& row, const std::string& json_value_array) {
  row.clear();

  rapidjson::Document document;
  auto status = ParseRowData(document, json_value_array);
  if (!status.ok()) {
    return status;
  }

  // We are going to ignore the last 3 columns column, but make sure they
  // are present so that we know if the schema is correct
  if (document.Size() != 6U) {
    return osquery::Status(1, "Wrong column count");
  }

  row["address"] = document[0].IsNull() ? "" : document[0].GetString();
  row["domain"] = document[1].IsNull() ? "" : document[1].GetString();

  row["sinkhole"] =
      document[2].IsNull() ? "127.0.0.1" : document[2].GetString();

  row["address_type"] = document[5].IsNull() ? "" : document[5].GetString();
  if (row["address_type"] != "ipv4" && row["address_type"] != "ipv6") {
    row["address_type"] = "ipv4";
  }

  return osquery::Status(0, "OK");
}

osquery::Status HostBlacklistTable::PrepareInsertData(osquery::Row& row) {
  bool use_ipv4 = (row["address_type"] == "ipv4");

  // Get the address from the domain
  if (row["address"].empty() && !row["domain"].empty()) {
    auto status =
        DomainToAddress(row.at("address"), row.at("domain"), use_ipv4);
    if (!status.ok()) {
      return status;
    }
  }

  // Get the domain from the address
  else if (!row["address"].empty() && row["domain"].empty()) {
    auto status = AddressToDomain(row.at("domain"), row.at("address"));
    if (!status.ok()) {
      return status;
    }
  }

  return osquery::Status(0, "OK");
}

bool HostBlacklistTable::IsInsertDataValid(const osquery::Row& row) {
  auto value_it = row.find("address");
  if (value_it == row.end()) {
    return false;
  }

  auto address = value_it->second;
  if (address.empty() || !ValidateIPAddress(address)) {
    return false;
  }

  value_it = row.find("domain");
  if (value_it == row.end()) {
    return false;
  }

  auto domain = value_it->second;
  if (domain.empty()) {
    return false;
  }

  value_it = row.find("sinkhole");
  if (value_it == row.end()) {
    return false;
  }

  auto sinkhole = value_it->second;
  if (sinkhole.empty() || !ValidateIPAddress(sinkhole)) {
    return false;
  }

  return true;
}

std::string HostBlacklistTable::GeneratePrimaryKey(const HostRule& rule) {
  return rule.domain;
}

RowID HostBlacklistTable::GenerateRowID() {
  static std::uint32_t generator = 0U;

  generator = (generator + 1) & 0x7FFFFFFFU;
  return generator;
}

void HostBlacklistTable::loadConfiguration() {
  try {
    // Load the configuration file
    if (!b_fs::exists(d->configuration_file_path)) {
      return;
    }

    b_fs::ifstream configuration_file(d->configuration_file_path);
    if (!configuration_file) {
      return;
    }

    b_arc::text_iarchive archive(configuration_file);

    HostRuleMap data;
    archive >> data;

    // Perform some validation
    for (auto& p : data) {
      auto& primary_key = p.first;
      auto& rule = p.second;

      boost::algorithm::trim(rule.address);
      boost::algorithm::trim(rule.domain);
      boost::algorithm::trim(rule.sinkhole);

      if (rule.address.empty() || rule.domain.empty() ||
          rule.sinkhole.empty()) {
        continue;
      }

      if (!ValidateIPAddress(rule.address) ||
          !ValidateIPAddress(rule.sinkhole)) {
        VLOG(1) << "Removing invalid/broken rule: " << rule.address << "/"
                << rule.domain << "/" << rule.sinkhole;
        continue;
      }

      d->data.insert(p);
      d->row_id_to_pkey.insert({GenerateRowID(), primary_key});
    }

    // Re-apply each loaded rule
    for (const auto& pair : d->data) {
      const auto& rule = pair.second;

      if (rule.address.empty() || rule.domain.empty() ||
          rule.sinkhole.empty()) {
        continue;
      }

      auto fw_status = GetFirewall().addHostToBlacklist(rule.address);
      auto hosts_status = d->hosts_file->addHost(rule.domain, rule.sinkhole);

      if ((!fw_status.success() &&
           fw_status.detail() != IFirewall::Detail::AlreadyExists) ||
          (!hosts_status.success() &&
           hosts_status.detail() != IHostsFile::Detail::AlreadyExists)) {
        VLOG(1) << "Failed to restore the following rule: " << rule.address
                << "/" << rule.domain << " -> " << rule.sinkhole;
      }
    }

  } catch (...) {
    VLOG(1) << "Failed to load the saved configuration";
  }
}

void HostBlacklistTable::saveConfiguration() {
  try {
    b_fs::ofstream configuration_file(d->configuration_file_path);
    if (!configuration_file) {
      return;
    }

    b_arc::text_oarchive archive(configuration_file);
    archive << d->data;

  } catch (...) {
    VLOG(1) << "Failed to save the configuration";
  }
}

osquery::Status HostBlacklistTable::DomainToAddress(std::string& address,
                                                    const std::string& domain,
                                                    bool use_ipv4) {
  address.clear();

  try {
    b_asio::io_service io_service;
    b_ip::tcp::resolver resolver(io_service);

    // clang-format off
    b_ip::tcp::resolver::query query(
      use_ipv4 ? b_ip::tcp::v4() : b_ip::tcp::v6(),
      domain, ""
    );
    // clang-format on

    b_ip::tcp::resolver::iterator end_it;
    for (auto resolver_it = resolver.resolve(query); resolver_it != end_it;
         resolver_it++) {
      auto endpoint = resolver_it->endpoint();

      const auto& address_obj = endpoint.address();

      if (address_obj.is_v4() == use_ipv4) {
        address = address_obj.to_string();
        break;
      }
    }

    if (address.empty()) {
      throw std::exception();
    }

    return osquery::Status(0, "OK");

  } catch (...) {
    return osquery::Status(1,
                           "Failed to resolve the following domain: " + domain);
  }
}

osquery::Status HostBlacklistTable::AddressToDomain(
    std::string& domain, const std::string& address) {
  domain.clear();

  try {
    b_asio::io_service io_service;
    b_ip::tcp::resolver resolver(io_service);

    auto dot_count = std::count(address.begin(), address.end(), '.');
    bool use_ipv4 = (dot_count == 3);

    b_ip::tcp::endpoint endpoint;
    if (use_ipv4) {
      auto ip_address = b_ip::address_v4::from_string(address);
      endpoint.address(ip_address);

    } else {
      auto ip_address = b_ip::address_v6::from_string(address);
      endpoint.address(ip_address);
    }

    auto resolver_it = resolver.resolve(endpoint);

    b_ip::tcp::resolver::iterator end_it;
    if (resolver_it == end_it) {
      throw std::exception();
    }

    domain = resolver_it->host_name();
    if (domain.empty()) {
      throw std::exception();
    }

    return osquery::Status(0, "OK");

  } catch (...) {
    return osquery::Status(
        1, "Failed to reverse lookup the following address: " + address);
  }
}
} // namespace trailofbits
