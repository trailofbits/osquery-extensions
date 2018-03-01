#include "firewall.h"

#include <trailofbits/extutils.h>

#include <boost/algorithm/string.hpp>

#include <iostream>
#include <mutex>
#include <vector>

namespace trailofbits {
const std::string pfctl = "/sbin/pfctl";

const std::string primary_anchor = "osquery_firewall_pri";
const std::string secondary_anchor = "osquery_firewall_sec";

const std::string blocked_hosts_table = "blocked_hosts";

struct Firewall::PrivateData final {
  std::string pf_token;
  std::mutex mutex;

  std::vector<PortRule> saved_port_rules;
  std::vector<std::string> saved_host_table;

  std::vector<PortRule> active_port_rules;
  std::vector<std::string> active_host_table;
};

Firewall::Status Firewall::create(std::unique_ptr<IFirewall>& obj) {
  try {
    auto ptr = new Firewall();
    obj.reset(ptr);

    return Status(true);

  } catch (const std::bad_alloc&) {
    return Status(false, Detail::MemoryAllocationError);

  } catch (const Status& status) {
    return status;
  }
}

Firewall::~Firewall() {
  // We could maybe log this error
  auto status = disableFirewall(d->pf_token);
  static_cast<void>(status);
}

Firewall::Status Firewall::addPortToBlacklist(
    std::uint16_t port,
    Firewall::TrafficDirection direction,
    Firewall::Protocol protocol) {
  std::lock_guard<std::mutex> lock(d->mutex);
  PortRule new_rule = {port, direction, protocol};

  // clang-format off
  auto it = std::find_if(
    d->saved_port_rules.begin(),
    d->saved_port_rules.end(),

    [new_rule](const PortRule &existing_rule) {
      return (
        new_rule.port == existing_rule.port &&
        new_rule.direction == existing_rule.direction &&
        new_rule.protocol == existing_rule.protocol
      );
    }
  );
  // clang-format on

  if (it != d->saved_port_rules.end()) {
    return Status(false, Detail::AlreadyExists);
  }

  d->saved_port_rules.push_back(new_rule);
  return applyFirewallRules();
}

Firewall::Status Firewall::removePortFromBlacklist(
    std::uint16_t port,
    Firewall::TrafficDirection direction,
    Firewall::Protocol protocol) {
  std::lock_guard<std::mutex> lock(d->mutex);
  PortRule new_rule = {port, direction, protocol};

  // clang-format off
  auto it = std::find_if(
    d->saved_port_rules.begin(),
    d->saved_port_rules.end(),

    [new_rule](const PortRule &existing_rule) {
      return (
        new_rule.port == existing_rule.port &&
        new_rule.direction == existing_rule.direction &&
        new_rule.protocol == existing_rule.protocol
      );
    }
  );
  // clang-format on

  if (it == d->saved_port_rules.end()) {
    return Status(false, Detail::NotFound);
  }

  d->saved_port_rules.erase(it);
  return applyFirewallRules();
}

Firewall::Status Firewall::enumerateBlacklistedPorts(
    bool (*callback)(std::uint16_t port,
                     Firewall::TrafficDirection direction,
                     Firewall::Protocol protocol,
                     Firewall::State state,
                     void* user_defined),
    void* user_defined) {
  auto status = readFirewallState();
  if (!status.success()) {
    return status;
  }

  std::vector<PortRule> saved_rules;
  std::vector<PortRule> active_rules;

  {
    std::lock_guard<std::mutex> lock(d->mutex);
    saved_rules = d->saved_port_rules;
    active_rules = d->active_port_rules;
  }

  for (const auto& saved_rule : saved_rules) {
    // clang-format off
    auto rule_it = std::find_if(
      active_rules.begin(),
      active_rules.end(),

      [saved_rule](const PortRule &active_rule) {
        return (
          saved_rule.port == active_rule.port &&
          saved_rule.direction == active_rule.direction &&
          saved_rule.protocol == active_rule.protocol
        );
      }
    );
    // clang-format on

    State rule_state =
        (rule_it == active_rules.end() ? State::Pending : State::Active);
    if (!callback(saved_rule.port,
                  saved_rule.direction,
                  saved_rule.protocol,
                  rule_state,
                  user_defined)) {
      break;
    }
  }

  return Status(true);
}

Firewall::Status Firewall::addHostToBlacklist() {
  return Status(true);
}

Firewall::Status Firewall::removeHostFromBlacklist() {
  return Status(true);
}

Firewall::Status Firewall::enumerateBlacklistedHosts() const {
  return Status(true);
}

Firewall::Firewall() : d(new PrivateData) {
  auto status = enableFirewall(d->pf_token);
  if (!status.success()) {
    throw status;
  }

  status = applyFirewallRules();
  if (!status.success()) {
    throw status;
  }
}

Firewall::Status Firewall::readFirewallState() {
  // Read the current settings
  std::string anchor_rules;
  auto status = ReadAnchor(anchor_rules, primary_anchor);
  if (!status.success()) {
    return status;
  }

  if (anchor_rules.empty()) {
    return Status(true);
  }

  std::string blacklist_table_contents;
  status =
      ReadTable(blacklist_table_contents, primary_anchor, blocked_hosts_table);
  if (!status.success()) {
    return status;
  }

  // Parse the output of pfctl
  if (!IsHostBlacklistTableActive(anchor_rules, blocked_hosts_table)) {
    return Status(false, Detail::QueryError);
  }

  std::vector<PortRule> applied_port_rules;
  status = ParsePortRulesFromAnchor(anchor_rules, applied_port_rules);
  if (!status.success()) {
    return status;
  }

  std::vector<std::string> host_list;
  ParseTable(blacklist_table_contents, host_list);

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    d->active_port_rules = std::move(applied_port_rules);
    d->active_host_table = std::move(host_list);
  }

  return Status(true);
}

Firewall::Status Firewall::applyFirewallRules() {
  auto new_rules = GenerateRules(
      blocked_hosts_table, d->saved_host_table, d->saved_port_rules);

  // Copy the ruleset of the primary anchor to the secondary one; this
  // way, we don't end up running without rules while we make our changes
  ProcessOutput proc_output;

  if (!ExecuteProcess(
          proc_output, pfctl, {"-a", primary_anchor, "-s", "rules"})) {
    return Status(false, Detail::ExecError);
  }

  auto old_ruleset = std::move(proc_output.std_output);
  proc_output = {};

  if (!old_ruleset.empty()) {
    if (!ExecuteProcess(proc_output,
                        pfctl,
                        {"-a", secondary_anchor, "-f", "-"},
                        old_ruleset)) {
      return Status(false, Detail::ExecError);
    }

    if (proc_output.exit_code != 0) {
      std::cerr << "Failed to set the secondary anchor\n";
      return Status(false, Detail::Undetermined);
    }
  }

  // Apply the new ruleset to the primary anchor
  if (!ExecuteProcess(
          proc_output, pfctl, {"-a", primary_anchor, "-f", "-"}, new_rules)) {
    return Status(false, Detail::ExecError);
  }

  if (proc_output.exit_code != 0) {
    std::cerr << "Failed to set the firewall rules\n";
    return Status(false, Detail::Undetermined);
  }

  // Erase the secondary anchor
  if (!old_ruleset.empty()) {
    if (!ExecuteProcess(
            proc_output, pfctl, {"-a", secondary_anchor, "-F", "all"})) {
      return Status(false, Detail::ExecError);
    }

    if (proc_output.exit_code != 0) {
      std::cerr << "Failed to flush the secondary anchor\n";
      return Status(false, Detail::Undetermined);
    }
  }

  return Status(true);
}

Firewall::Status Firewall::enableFirewall(std::string& token) {
  ProcessOutput proc_output;
  if (!ExecuteProcess(proc_output, pfctl, {"-E"})) {
    return Status(false, Detail::ExecError);
  }

  if (proc_output.std_error.find("pf enabled") == std::string::npos) {
    return Status(false, Detail::InitializationError);
  }

  auto token_start = proc_output.std_error.find("Token : ");
  if (token_start == std::string::npos) {
    return Status(false, Detail::InitializationError);
  }
  token_start += 8U;

  auto token_end = proc_output.std_error.find("\n", token_start);
  if (token_end == std::string::npos) {
    return Status(false, Detail::InitializationError);
  }

  token = proc_output.std_error.substr(token_start, (token_end - token_start));
  if (token.empty()) {
    return Status(false, Detail::InitializationError);
  }

  return Status(true);
}

Firewall::Status Firewall::disableFirewall(const std::string& token) {
  ProcessOutput proc_output;
  if (!ExecuteProcess(proc_output, pfctl, {"-X", token})) {
    return Status(false, Detail::ExecError);
  }

  if (proc_output.std_error.find("disable request successful") ==
      std::string::npos) {
    return Status(false, Detail::CleanupError);
  }

  return Status(true);
}

Firewall::Status Firewall::ReadAnchor(std::string& contents,
                                      const std::string& anchor) {
  contents.clear();

  // Dump the anchor rules; the command will return 0 even when some errors are
  // returned. If we are here, then it means that the anchor exists.
  ProcessOutput proc_output;
  if (!ExecuteProcess(proc_output, pfctl, {"-a", anchor, "-s", "rules"})) {
    return Status(false, Detail::ExecError);
  }

  if (proc_output.exit_code != 0 ||
      proc_output.std_error.find("pfctl: DIOCGETRULES: Invalid argument") !=
          std::string::npos ||
      proc_output.std_output.empty()) {
    return Status(false, Detail::QueryError);
  }

  contents = proc_output.std_output;
  return Status(true);
}

Firewall::Status Firewall::ReadTable(std::string& contents,
                                     const std::string& anchor,
                                     const std::string& table) {
  // Dump the blocked hosts table; the command will return -1 and print an error
  // if the table is not found
  ProcessOutput proc_output;
  if (!ExecuteProcess(proc_output, pfctl, {"-a", anchor, "-t", table})) {
    return Status(false, Detail::ExecError);
  }

  // It is not an error if the table is not found
  if (proc_output.std_error.find("pfctl: Table does not exist.") !=
      std::string::npos) {
    return Status(true);
  }

  if (proc_output.exit_code != 0) {
    return Status(false, Detail::QueryError);
  }

  contents = proc_output.std_output;
  return Status(true);
}

Firewall::Status Firewall::ParsePortRulesFromAnchor(
    const std::string& contents, std::vector<PortRule>& port_rule_list) {
  /*
    Port rules

      outbound
      block drop out quick proto tcp from any to any port = 3434

      inbound
      block drop in quick proto tcp from any to any port = 3434

      inbound/outbound
      block drop quick proto tcp from any to any port = 3434
  */

  // This is a private namespace; ignore everything that does not match our
  // syntax
  auto rule_list = SplitString(contents, '\n');
  for (const auto& rule : rule_list) {
    const char* ptr = rule.data();
    if (std::strncmp(ptr, "block drop ", 11U) != 0) {
      continue;
    }
    ptr += 11U;

    TrafficDirection direction;
    bool both_directions = true;
    if (std::strncmp(ptr, "in ", 3U) == 0) {
      direction = TrafficDirection::Inbound;
      both_directions = false;
      ptr += 3U;

    } else if (std::strncmp(ptr, "out ", 4U) == 0) {
      direction = TrafficDirection::Outbound;
      both_directions = false;
      ptr += 4U;

    } else if (std::strncmp(ptr, "quick ", 6U) != 0) {
      continue;
    }

    if (std::strncmp(ptr, "quick proto ", 12U) != 0) {
      continue;
    }
    ptr += 12U;

    bool is_tcp;
    if (std::strncmp(ptr, "tcp ", 4U) == 0) {
      is_tcp = true;
    } else if (std::strncmp(ptr, "udp ", 4U) == 0) {
      is_tcp = false;
    } else {
      continue;
    }
    ptr += 4U;

    if (std::strncmp(ptr, "from any to any port = ", 23U) != 0) {
      continue;
    }
    ptr += 23U;

    const char* port = ptr;
    for (auto i = 0U; port[i] != 0; i++) {
      if (!::isdigit(port[i])) {
        port = nullptr;
        break;
      }
    }

    if (port == nullptr) {
      continue;
    }

    PortRule port_rule;
    port_rule.port =
        static_cast<std::uint16_t>(std::strtoull(port, nullptr, 10));
    if (port_rule.port == 0 || port_rule.port > 65535) {
      continue;
    }

    port_rule.protocol = (is_tcp ? Protocol::TCP : Protocol::UDP);

    if (both_directions) {
      port_rule.direction = TrafficDirection::Inbound;
      port_rule_list.push_back(port_rule);

      port_rule.direction = TrafficDirection::Outbound;
      port_rule_list.push_back(port_rule);
    } else {
      port_rule.direction = direction;
      port_rule_list.push_back(port_rule);
    }
  }

  return Status(true);
}

bool Firewall::IsHostBlacklistTableActive(const std::string& contents,
                                          const std::string& table) {
  /*
    Host rules - using tables

      block drop from <hosts> to any
      block drop from any to <hosts>
  */

  // This is a private namespace; ignore everything that does not match our
  // syntax

  // clang-format off
  auto rule_list = {
    std::string("block drop from <") + table + "> to any",
    std::string("block drop from any to <") + table + ">"
  };
  // clang-format on

  for (const auto& rule : rule_list) {
    if (contents.find(rule) == std::string::npos) {
      return false;
    }
  }

  return true;
}

std::string Firewall::GenerateTable(
    const std::string& table_name,
    const std::vector<std::string> blocked_hosts) {
  std::stringstream str_helper;
  str_helper << "table <" << table_name << "> persist { ";

  for (auto it = blocked_hosts.begin(); it != blocked_hosts.end(); it++) {
    str_helper << (*it);
    if (std::next(it, 1) != blocked_hosts.end()) {
      str_helper << ", ";
    }
  }

  str_helper << " }\n";

  return str_helper.str();
}

std::string Firewall::GenerateHostRules(
    const std::string& table_name,
    const std::vector<std::string> blocked_hosts) {
  std::stringstream str_helper;
  str_helper << GenerateTable(table_name, blocked_hosts);

  str_helper << "block drop from <" << table_name << "> to any\n";
  str_helper << "block drop from any to <" << table_name << ">\n";

  return str_helper.str();
}

std::string Firewall::GeneratePortRules(const std::vector<PortRule>& rules) {
  std::stringstream str_helper;

  for (const auto& rule : rules) {
    str_helper << "block drop "
               << (rule.direction == TrafficDirection::Inbound ? "in" : "out")
               << " quick proto "
               << (rule.protocol == Protocol::TCP ? "tcp" : "udp")
               << " to any port " << rule.port << "\n";
  }

  return str_helper.str();
}

std::string Firewall::GenerateRules(
    const std::string& blocked_hosts_table_name,
    const std::vector<std::string> blocked_hosts,
    const std::vector<PortRule>& port_rules) {
  std::stringstream str_helper;
  str_helper << GenerateHostRules(blocked_hosts_table_name, blocked_hosts);
  str_helper << GeneratePortRules(port_rules);

  return str_helper.str();
}

void Firewall::ParseTable(const std::string& contents,
                          std::vector<std::string>& table) {
  table = SplitString(contents, '\n');
}

Firewall::Status CreateFirewallObject(std::unique_ptr<IFirewall>& obj) {
  return Firewall::create(obj);
}
} // namespace trailofbits
