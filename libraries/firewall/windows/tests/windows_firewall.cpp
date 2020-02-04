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

#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace trailofbits {
namespace {
std::string GetPortRuleDescription(const Firewall::PortRule& port_rule) {
  std::stringstream stream;
  stream << port_rule.port << "/";

  if (port_rule.protocol == IFirewall::Protocol::TCP) {
    stream << "tcp";
  } else {
    stream << "udp";
  }
  stream << "/";

  if (port_rule.direction == IFirewall::TrafficDirection::Inbound) {
    stream << "inbound";
  } else {
    stream << "outbound";
  }

  return stream.str();
}
} // namespace
TEST(WindowsFirewallTests, ParseFirewallStateBlockTest) {
  std::stringstream test_input_str;
  test_input_str
      << "Enabled:                              Yes\n"
      << "Direction:                            In\n"
      << "Profiles:                             Domain, Private, Public\n"
      << "Grouping:                                                \n"
      << "LocalIP:                              Any\n"
      << "RemoteIP:                             Any\n"
      << "Protocol:                             TCP\n"
      << "LocalPort:                            44444\n"
      << "RemotePort:                           Any\n"
      << "Edge traversal:                       No\n"
      << "Action:                               Block\n"
      << "Ok.";

  // clang-format off
		const std::vector<std::string> expected_output = {
			"44444/tcp/inbound",
		};
  // clang-format on

  std::vector<std::string> actual_output;

  std::string line("testRule34");

  Firewall::Rule rule;
  bool rval = Firewall::ParseFirewallRuleBlock(test_input_str, line, rule);
  EXPECT_TRUE(rval);

  bool is_port_rule = (rule.which() == 0);
  EXPECT_TRUE(is_port_rule);

  if (is_port_rule) {
    auto port_rule = boost::get<Firewall::PortRule>(rule);

    auto port_rule_description = GetPortRuleDescription(port_rule);
    actual_output.push_back(port_rule_description);
  }

  EXPECT_EQ(actual_output.size(), expected_output.size());

  if (actual_output.size() == expected_output.size()) {
    for (auto i = 0U; i < actual_output.size(); i++) {
      EXPECT_EQ(actual_output.at(i), expected_output.at(i));
    }
  }
}

TEST(WindowsFirewallTests, ParseFirewallStateTest) {
  std::stringstream test_input_stream;
  test_input_stream
      << "RuleName:                             testBlock34\n"
      << "-----------------------------------------------------------------\n"
      << "Enabled:                              Yes\n"
      << "Direction:                            In\n"
      << "Profiles:                             Domain, Private, Public\n"
      << "Grouping:                                                \n"
      << "LocalIP:                              Any\n"
      << "RemoteIP:                             Any\n"
      << "Protocol:                             TCP\n"
      << "LocalPort:                            44444\n"
      << "RemotePort:                           Any\n"
      << "Edge traversal:                       No\n"
      << "Action:                               Block\n"
      << "\n"
      << "RuleName:                             blockipin\n"
      << "-----------------------------------------------------------------\n"
      << "Enabled:                              Yes\n"
      << "Direction:                            In\n"
      << "Profiles:                             Domain, Private, Public\n"
      << "Grouping:                                                \n"
      << "LocalIP:                              Any\n"
      << "RemoteIP:                             55.55.55.55\n"
      << "Protocol:                             TCP\n"
      << "LocalPort:                            Any\n"
      << "RemotePort:                           Any\n"
      << "Edge traversal:                       No\n"
      << "Action:                               Block\n"
      << "\n"
      << "RuleName:                             blockipout\n"
      << "-----------------------------------------------------------------\n"
      << "Enabled:                              Yes\n"
      << "Direction:                            Out\n"
      << "Profiles:                             Domain, Private, Public\n"
      << "Grouping:                                                \n"
      << "LocalIP:                              Any\n"
      << "RemoteIP:                             55.55.55.55\n"
      << "Protocol:                             TCP\n"
      << "LocalPort:                            Any\n"
      << "RemotePort:                           Any\n"
      << "Edge traversal:                       No\n"
      << "Action:                               Block\n"
      << "Ok.";

  const std::vector<std::string> expected_ports = {
      "44444/tcp/inbound",
  };
  const std::vector<std::string> expected_ips = {
      "55.55.55.55",
  };
  std::vector<Firewall::PortRule> port_rules;
  std::set<std::string> blocked_hosts;
  Firewall::ParseFirewallState(
      port_rules, blocked_hosts, test_input_stream.str());

  if (port_rules.size() == expected_ports.size()) {
    for (auto i = 0U; i < port_rules.size(); ++i) {
      EXPECT_EQ(GetPortRuleDescription(port_rules[i]), expected_ports[i]);
    }
  }
  if (blocked_hosts.size() == expected_ips.size()) {
    for (auto i = 0U; i < blocked_hosts.size(); ++i) {
      EXPECT_NE(blocked_hosts.find(expected_ips[i]), blocked_hosts.end());
    }
  }
}
} // namespace trailofbits
