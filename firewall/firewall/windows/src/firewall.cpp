#include "firewall.h"

#include <trailofbits/extutils.h>

#include <cctype>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>

namespace trailofbits {

const std::string netsh = "C:\\Windows\\System32\\netsh.exe";

// utility functions for string parsing

std::string& trim(std::string& s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
            return !std::isspace(ch);
          }));

  s.erase(std::find_if(
              s.rbegin(), s.rend(), [](int ch) { return !std::isspace(ch); })
              .base(),
          s.end());
  return s;
}

// parses lines of the format "some key:          some value     "
// where whitespace between key and value is of uncertain nonzero length
// and whitespace after value is of uncertain length
void collectKeyValuePair(const std::string& line,
                         std::unordered_map<std::string, std::string>& values) {
  size_t key_end = line.find(":");
  if (key_end == std::string::npos) {
    return;
  }

  values.emplace(line.substr(0, key_end), trim(line.substr(key_end + 1)));
}

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

  const char* dir =
      (direction == TrafficDirection::Inbound ? "dir=in" : "dir=out");

  const char* proto =
      (protocol == Protocol::TCP ? "protocol=TCP" : "protocol=UDP");

  std::stringstream rulename, portstr;
  rulename << "name=\"BlockPort" << port
           << (direction == TrafficDirection::Inbound ? "in" : "out") << "\"";

  portstr << (direction == TrafficDirection::Inbound ? "local" : "remote")
          << "port=" << port;

  ProcessOutput proc_output;
  if (!ExecuteProcess(proc_output,
                      netsh,
                      {"advfirewall",
                       "firewall",
                       "add",
                       "rule",
                       rulename.str(),
                       proto,
                       dir,
                       portstr.str(),
                       "action=block"}) ||
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

  std::stringstream rule_name;
  rule_name << "name=\"" << (*rule_it).name << "\"";

  ProcessOutput proc_output;
  if (!ExecuteProcess(
          proc_output,
          netsh,
          {"advfirewall", "firewall", "delete", "rule", rule_name.str()}) ||
      proc_output.exit_code != 0) {
    return Status(false, Detail::ExecError);
  }
  return Status(true);
}

void Firewall::getHostBlockRuleNames(const std::string& state,
                                     const std::string& host,
                                     std::set<std::string>& rule_names) {
  std::stringstream stream(state);

  while (true) {
    if (stream.eof()) {
      break;
    }
    std::string line;
    std::getline(stream, line);
    if (line.find("Rule Name:") == std::string::npos) {
      continue;
    }

    std::string ruleName = trim(line.substr(line.find_first_of(":") + 1));

    std::getline(stream, line); // discard, all hyphens
    Rule rule_var;
    if (ParseFirewallRuleBlock(stream, ruleName, rule_var)) {
      if (0 == rule_var.which()) {
        continue;
      } else {
        auto rule = boost::get<IPRule>(rule_var);
        if (rule.address.compare(host) != 0) {
          continue;
        }
        rule_names.insert(ruleName);
      }
    }
  }
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

  std::set<std::string> host_block_rule_names;
  getHostBlockRuleNames(firewall_state, host, host_block_rule_names);

  for (auto it : host_block_rule_names) {
    std::stringstream rulename;
    rulename << "name=\"" << it << "\"";
    ProcessOutput proc_output;
    if (!ExecuteProcess(
            proc_output,
            netsh,
            {"advfirewall", "firewall", "delete", "rule", rulename.str()}) ||
        proc_output.exit_code != 0) {
      return Status(false, Detail::ExecError);
    }
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
  if (!ExecuteProcess(proc_output,
                      netsh,
                      {"advfirewall",
                       "firewall",
                       "show",
                       "rule",
                       "name=all",
                       "status=enabled"}) ||
      proc_output.exit_code != 0) {
    return Status(false, Detail::ExecError);
  }

  state = std::move(proc_output.std_output);
  return Status(true);
}

/*
 * Rule Name:                            testRule34
 * ----------------------------------------------------------------------
 * Enabled:                              Yes
 * Direction:                            In
 * Profiles:                             Domain,Private,Public
 * Grouping:
 * LocalIP:                              Any
 * RemoteIP:                             Any
 * Protocol:                             TCP
 * LocalPort:                            44444
 * RemotePort:                           Any
 * Edge traversal:                       No
 * Action:                               Block
 */

void Firewall::ParseFirewallState(std::vector<PortRule>& port_rules,
                                  std::set<std::string>& blocked_hosts,
                                  const std::string& state) {
  port_rules.clear();
  blocked_hosts.clear();

  std::stringstream stream(state);

  using IPRuleState = std::set<TrafficDirection>;
  std::unordered_map<std::string, IPRuleState> ip_rules;

  while (true) {
    if (stream.eof()) {
      break;
    }
    std::string line;
    std::getline(stream, line);
    if (line.find("Rule Name:") == std::string::npos) {
      continue;
    }

    std::string ruleName = trim(line.substr(line.find_first_of(":") + 1));

    std::getline(stream, line); // discard, all hyphens
    Rule rule_var;
    if (ParseFirewallRuleBlock(stream, ruleName, rule_var)) {
      if (0 == rule_var.which()) {
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
  }
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

  std::stringstream in_name, out_name, remotehost;
  in_name << "name=\"Block" << host << "In\"";
  out_name << "name=\"Block" << host << "Out\"";
  remotehost << "remoteip=" << host;

  std::vector<std::string> in_args = {"advfirewall",
                                      "firewall",
                                      "add",
                                      "rule",
                                      in_name.str(),
                                      "dir=in",
                                      "action=block",
                                      remotehost.str()};
  ProcessOutput proc_output;
  if (!ExecuteProcess(proc_output, netsh, in_args) ||
      proc_output.exit_code != 0) {
    return Status(false, Detail::ExecError);
  }

  std::vector<std::string> out_args = {"advfirewall",
                                       "firewall",
                                       "add",
                                       "rule",
                                       out_name.str(),
                                       "dir=out",
                                       "action=block",
                                       remotehost.str()};
  if (!ExecuteProcess(proc_output, netsh, out_args) ||
      proc_output.exit_code != 0) {
    return Status(false, Detail::ExecError);
  }

  return Status(true);
}

bool Firewall::ParseFirewallRuleBlock(std::stringstream& stream,
                                      const std::string& rule_name,
                                      Rule& rule) {
  std::unordered_map<std::string, std::string> values;

  std::string line;
  std::getline(stream, line);
  while (line.find(":") != std::string::npos) {
    collectKeyValuePair(line, values);
    std::getline(stream, line);
  }

  if (values["Action"].compare("Block") != 0) {
    return false; // don't care about non block rules at the moment
  }

  TrafficDirection direction;
  if (values["Direction"].compare("In") == 0) {
    direction = TrafficDirection::Inbound;
  } else if (values["Direction"].compare("Out") == 0) {
    direction = TrafficDirection::Outbound;
  } else {
    return false;
  }

  if (direction == TrafficDirection::Inbound &&
      values["LocalPort"].length() != 0 &&
      values["LocalPort"].compare("Any") != 0) {
    // blocking a port
    Protocol protocol;
    if (values["Protocol"].compare("TCP") == 0) {
      protocol = Protocol::TCP;
    } else if (values["Protocol"].compare("UDP") == 0) {
      protocol = Protocol::UDP;
    } else {
      return false;
    }

    auto port = static_cast<std::uint16_t>(
        std::strtoull(values["LocalPort"].c_str(), NULL, 10));
    if (port == 0 || port > 65535) {
      return false;
    }

    PortRule port_rule = {port, direction, protocol, rule_name};
    rule = port_rule;
    return true;
  } else if (direction == TrafficDirection::Outbound &&
             values["RemotePort"].length() != 0 &&
             values["RemotePort"].compare("Any") != 0) {
    // blocking a port
    Protocol protocol;
    if (values["Protocol"].compare("TCP") == 0) {
      protocol = Protocol::TCP;
    } else if (values["Protocol"].compare("UDP") == 0) {
      protocol = Protocol::UDP;
    } else {
      return false;
    }

    auto port = static_cast<std::uint16_t>(
        std::strtoull(values["RemotePort"].c_str(), NULL, 10));
    if (port == 0 || port > 65535) {
      return false;
    }

    PortRule port_rule = {port, direction, protocol, rule_name};
    rule = port_rule;
    return true;
  } else if (values["RemoteIP"].length() != 0 &&
             values["RemoteIP"].compare("Any") != 0) {
    // blocking an address
    std::string mask = "/32";
    if (0 !=
        values["RemoteIP"].compare(
            values["RemoteIP"].length() - mask.length(), mask.length(), mask)) {
      return false;
    }
    IPRule ip_rule = {direction,
                      values["RemoteIP"].substr(
                          0, values["RemoteIP"].length() - mask.length())};
    rule = ip_rule;
    return true;
  }

  return false;
}

Firewall::Status CreateFirewallObject(std::unique_ptr<IFirewall>& obj) {
  return Firewall::create(obj);
}

} // namespace trailofbits
