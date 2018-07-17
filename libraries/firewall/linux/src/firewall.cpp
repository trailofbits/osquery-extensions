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

#include "firewall.h"

#include <trailofbits/extutils.h>

#include <iostream>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace trailofbits {
const std::string iptables = "/sbin/iptables";

struct Firewall::PrivateData final {
  std::mutex mutex;
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

Firewall::~Firewall() {}

Firewall::Status Firewall::addPortToBlacklist(
    std::uint16_t port,
    Firewall::TrafficDirection direction,
    Firewall::Protocol protocol) {
  std::lock_guard<std::mutex> lock(d->mutex);

  std::string firewall_state;
  auto status = ReadFirewallState(firewall_state);
  if (!status.success()) {
    return status;
  }

  std::vector<PortRule> port_rules;
  std::set<std::string> blocked_hosts;
  ParseFirewallState(port_rules, blocked_hosts, firewall_state);

  // clang-format off
  auto rule_it = std::find_if(
    port_rules.begin(),
    port_rules.end(),

    [port, direction, protocol](const PortRule &other) -> bool {
      return (
        other.port == port &&
        other.direction == direction &&
        other.protocol == protocol
      );
    }
  );
  // clang-format on

  if (rule_it != port_rules.end()) {
    return Status(false, Detail::AlreadyExists);
  }

  // Attempt to apply the iptables rule
  const char* chain_name =
      (direction == TrafficDirection::Inbound ? "INPUT" : "OUTPUT");

  const char* protocol_name = (protocol == Protocol::TCP ? "tcp" : "udp");

  ProcessOutput proc_output;
  if (!ExecuteProcess(proc_output,
                      iptables,
                      {"-A",
                       chain_name,
                       "-p",
                       protocol_name,
                       "--destination-port",
                       std::to_string(port),
                       "-j",
                       "DROP"}) ||
      proc_output.exit_code != 0) {
    return Status(false, Detail::ExecError);
  }

  return Status(true);
}

Firewall::Status Firewall::removePortFromBlacklist(
    std::uint16_t port,
    Firewall::TrafficDirection direction,
    Firewall::Protocol protocol) {
  std::lock_guard<std::mutex> lock(d->mutex);

  std::string firewall_state;
  auto status = ReadFirewallState(firewall_state);
  if (!status.success()) {
    return status;
  }

  std::vector<PortRule> port_rules;
  std::set<std::string> blocked_hosts;
  ParseFirewallState(port_rules, blocked_hosts, firewall_state);

  // clang-format off
  auto rule_it = std::find_if(
    port_rules.begin(),
    port_rules.end(),

    [port, direction, protocol](const PortRule &other) -> bool {
      return (
        other.port == port &&
        other.direction == direction &&
        other.protocol == protocol
      );
    }
  );
  // clang-format on

  if (rule_it == port_rules.end()) {
    return Status(false, Detail::NotFound);
  }

  // Attempt to remove the iptables rule
  const char* chain_name =
      (direction == TrafficDirection::Inbound ? "INPUT" : "OUTPUT");

  const char* protocol_name = (protocol == Protocol::TCP ? "tcp" : "udp");

  ProcessOutput proc_output;
  if (!ExecuteProcess(proc_output,
                      iptables,
                      {"-D",
                       chain_name,
                       "-p",
                       protocol_name,
                       "--destination-port",
                       std::to_string(port),
                       "-j",
                       "DROP"}) ||
      proc_output.exit_code != 0) {
    return Status(false, Detail::ExecError);
  }

  return Status(true);
}

Firewall::Status Firewall::enumerateBlacklistedPorts(
    bool (*callback)(std::uint16_t port,
                     Firewall::TrafficDirection direction,
                     Firewall::Protocol protocol,
                     void* user_defined),
    void* user_defined) {
  std::vector<PortRule> port_rules;
  std::set<std::string> blocked_hosts;

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    std::string firewall_state;
    auto status = ReadFirewallState(firewall_state);
    if (!status.success()) {
      return status;
    }

    ParseFirewallState(port_rules, blocked_hosts, firewall_state);
  }

  for (const auto& rule : port_rules) {
    if (!callback(rule.port, rule.direction, rule.protocol, user_defined)) {
      break;
    }
  }

  return Status(true);
}

Firewall::Status Firewall::addHostToBlacklist(const std::string& host) {
  std::lock_guard<std::mutex> lock(d->mutex);

  std::string firewall_state;
  auto status = ReadFirewallState(firewall_state);
  if (!status.success()) {
    return status;
  }

  std::vector<PortRule> port_rules;
  std::set<std::string> blocked_hosts;
  ParseFirewallState(port_rules, blocked_hosts, firewall_state);

  if (blocked_hosts.find(host) != blocked_hosts.end()) {
    return Status(false, Detail::AlreadyExists);
  }

  // Attempt to apply the iptables rule
  ProcessOutput proc_output;
  if (!ExecuteProcess(
          proc_output, iptables, {"-A", "INPUT", "-s", host, "-j", "DROP"}) ||
      proc_output.exit_code != 0) {
    return Status(false, Detail::ExecError);
  }

  if (!ExecuteProcess(
          proc_output, iptables, {"-A", "OUTPUT", "-d", host, "-j", "DROP"}) ||
      proc_output.exit_code != 0) {
    return Status(false, Detail::ExecError);
  }

  return Status(true);
}

Firewall::Status Firewall::removeHostFromBlacklist(const std::string& host) {
  std::lock_guard<std::mutex> lock(d->mutex);

  std::string firewall_state;
  auto status = ReadFirewallState(firewall_state);
  if (!status.success()) {
    return status;
  }

  std::vector<PortRule> port_rules;
  std::set<std::string> blocked_hosts;
  ParseFirewallState(port_rules, blocked_hosts, firewall_state);

  if (blocked_hosts.find(host) == blocked_hosts.end()) {
    return Status(false, Detail::NotFound);
  }

  // Attempt to apply the iptables rule
  ProcessOutput proc_output;
  if (!ExecuteProcess(
          proc_output, iptables, {"-D", "INPUT", "-s", host, "-j", "DROP"}) ||
      proc_output.exit_code != 0) {
    return Status(false, Detail::ExecError);
  }

  if (!ExecuteProcess(
          proc_output, iptables, {"-D", "OUTPUT", "-d", host, "-j", "DROP"}) ||
      proc_output.exit_code != 0) {
    return Status(false, Detail::ExecError);
  }

  return Status(true);
}

Firewall::Status Firewall::enumerateBlacklistedHosts(
    bool (*callback)(const std::string& host, void* user_defined),
    void* user_defined) {
  std::vector<PortRule> port_rules;
  std::set<std::string> blocked_hosts;

  {
    std::lock_guard<std::mutex> lock(d->mutex);

    std::string firewall_state;
    auto status = ReadFirewallState(firewall_state);
    if (!status.success()) {
      return status;
    }

    ParseFirewallState(port_rules, blocked_hosts, firewall_state);
  }

  for (const auto& host : blocked_hosts) {
    if (!callback(host, user_defined)) {
      break;
    }
  }

  return Status(true);
}

Firewall::Firewall() : d(new PrivateData) {}

Firewall::Status Firewall::ReadFirewallState(std::string& state) {
  ProcessOutput proc_output;
  if (!ExecuteProcess(proc_output, iptables, {"-S"}) ||
      proc_output.exit_code != 0) {
    return Status(false, Detail::ExecError);
  }

  state = std::move(proc_output.std_output);
  return Status(true);
}

void Firewall::ParseFirewallState(std::vector<PortRule>& port_rules,
                                  std::set<std::string>& blocked_hosts,
                                  const std::string& state) {
  port_rules.clear();
  blocked_hosts.clear();

  std::stringstream stream(state);

  using IPRuleState = std::set<TrafficDirection>;
  std::unordered_map<std::string, IPRuleState> ip_rules;

  while (true) {
    std::string line;
    std::getline(stream, line);

    Rule rule_var;
    if (ParseFirewallStateLine(rule_var, line)) {
      bool is_port_rule = (rule_var.which() == 0);

      if (is_port_rule) {
        auto rule = boost::get<PortRule>(rule_var);
        port_rules.push_back(rule);

      } else {
        // Accumulate each IP rule and save them when they are
        // complete (i.e.: both inbound and outbound traffic has
        // been blocked)
        auto rule = boost::get<IPRule>(rule_var);

        auto it = ip_rules.find(rule.address);
        if (it == ip_rules.end()) {
          ip_rules.insert({rule.address, {rule.direction}});

        } else {
          it->second.insert(rule.direction);

          if (it->second.size() == 2U) {
            blocked_hosts.insert(rule.address);
            ip_rules.erase(it);
          }
        }
      }
    }

    if (stream.eof()) {
      break;
    }
  }
}

bool Firewall::ParseFirewallStateLine(Rule& rule, const std::string& line) {
  /*
    IP
      Inbound
        -A INPUT -s 123.123.123.123/32 -j DROP

      Outbound
        -A OUTPUT -d 123.123.123.123/32 -j DROP

    Ports
      Inbound
        -A INPUT -p udp -m udp --dport 443 -j DROP
        -A INPUT -p tcp -m tcp --dport 443 -j DROP

      Outbound
        -A OUTPUT -p udp -m udp --dport 80 -j DROP
        -A OUTPUT -p tcp -m tcp --dport 80 -j DROP
  */

  auto ptr = line.data();

  TrafficDirection direction;
  if (std::strncmp(ptr, "-A INPUT ", 9) == 0) {
    ptr += 9;
    direction = TrafficDirection::Inbound;

  } else if (std::strncmp(ptr, "-A OUTPUT ", 10) == 0) {
    ptr += 10;
    direction = TrafficDirection::Outbound;

  } else {
    return false;
  }

  bool is_port_rule;
  if (std::strncmp(ptr, "-s ", 3) == 0) {
    ptr += 3;
    is_port_rule = false;

  } else if (std::strncmp(ptr, "-d ", 3) == 0) {
    ptr += 3;
    is_port_rule = false;

  } else if (std::strncmp(ptr, "-p ", 3) == 0) {
    ptr += 3;
    is_port_rule = true;
  } else {
    return false;
  }

  if (is_port_rule) {
    Protocol protocol;
    if (std::strncmp(ptr, "udp -m udp --dport ", 19) == 0) {
      ptr += 19;
      protocol = Protocol::UDP;

    } else if (std::strncmp(ptr, "tcp -m tcp --dport ", 19) == 0) {
      ptr += 19;
      protocol = Protocol::TCP;

    } else {
      return false;
    }

    char* end_ptr;
    auto port = static_cast<std::uint16_t>(std::strtoull(ptr, &end_ptr, 10));

    if (port == 0 || port > 65535) {
      return false;
    }

    ptr = end_ptr;

    if (std::strcmp(ptr, " -j DROP") != 0) {
      return false;
    }

    PortRule port_rule = {port, direction, protocol};
    rule = port_rule;

    return true;

  } else {
    std::string address;

    while (true) {
      if (*ptr == 0) {
        return false;
      } else if (*ptr == '/') {
        ptr++;
        break;
      }

      address.push_back(*ptr);
      ptr++;
    }

    while (true) {
      if (*ptr == 0) {
        return false;
      } else if (*ptr == ' ') {
        break;
      }

      ptr++;
    }

    if (std::strcmp(ptr, " -j DROP") != 0) {
      return false;
    }

    IPRule ip_rule = {direction, address};
    rule = ip_rule;

    return true;
  }
}

Firewall::Status CreateFirewallObject(std::unique_ptr<IFirewall>& obj) {
  return Firewall::create(obj);
}
} // namespace trailofbits
