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

#include <sstream>

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
TEST(IptablesFirewallTests, ParseFirewallStateLine) {
  const std::vector<std::string> test_input = {
      "-A INPUT -s 123.123.123.123/32 -j DROP",
      "-A OUTPUT -d 123.123.123.123/32 -j DROP",
      "-A INPUT -p udp -m udp --dport 443 -j DROP",
      "-A INPUT -p tcp -m tcp --dport 443 -j DROP",
      "-A OUTPUT -p udp -m udp --dport 80 -j DROP",
      "-A OUTPUT -p tcp -m tcp --dport 80 -j DROP",
      "-A OUTPUT -d 1.2.3.4/32 -j DROP",

      // Discarded
      "this is a test!"};

  // clang-format off
  const std::vector<std::string> expected_output = {
    "123.123.123.123/inbound",
    "123.123.123.123/outbound",
    "443/udp/inbound",
    "443/tcp/inbound",
    "80/udp/outbound",
    "80/tcp/outbound",
    "1.2.3.4/outbound"
  };
  // clang-format on

  std::vector<std::string> actual_output;

  for (const auto& line : test_input) {
    Firewall::Rule rule;
    if (!Firewall::ParseFirewallStateLine(rule, line)) {
      continue;
    }

    bool is_port_rule = (rule.which() == 0);
    if (is_port_rule) {
      auto port_rule = boost::get<Firewall::PortRule>(rule);

      auto port_rule_description = GetPortRuleDescription(port_rule);
      actual_output.push_back(port_rule_description);

    } else {
      auto ip_rule = boost::get<Firewall::IPRule>(rule);

      std::stringstream stream;
      stream << ip_rule.address << "/";

      if (ip_rule.direction == IFirewall::TrafficDirection::Inbound) {
        stream << "inbound";
      } else {
        stream << "outbound";
      }

      actual_output.push_back(stream.str());
    }
  }

  EXPECT_EQ(actual_output.size(), expected_output.size());

  if (actual_output.size() == expected_output.size()) {
    for (auto i = 0U; i < actual_output.size(); i++) {
      EXPECT_EQ(actual_output.at(i), expected_output.at(i));
    }
  }
}

TEST(IptablesFirewallTests, ParseFirewallState) {
  // clang-format off
  const std::string test_input = {
    "-A INPUT -s 123.123.123.123/32 -j DROP\n"
    "-A OUTPUT -d 123.123.123.123/32 -j DROP\n"
    "-A INPUT -p udp -m udp --dport 443 -j DROP\n"
    "-A INPUT -p tcp -m tcp --dport 443 -j DROP\n"
    "-A OUTPUT -p udp -m udp --dport 80 -j DROP\n"
    "-A OUTPUT -p tcp -m tcp --dport 80 -j DROP\n"

    // This is discarded because it is only partial (i.e.: the inbound
    // rule is missing)
    "-A OUTPUT -d 1.2.3.4/32 -j DROP\n"

    // Discarded
    "this is a test\n"
  };
  // clang-format on

  const std::set<std::string> expected_blocked_hosts = {"123.123.123.123"};

  const std::vector<std::string> expected_port_rules = {"443/udp/inbound",
                                                        "443/tcp/inbound",
                                                        "80/udp/outbound",
                                                        "80/tcp/outbound"};

  std::vector<Firewall::PortRule> actual_port_rules;
  std::set<std::string> actual_blocked_hosts;
  Firewall::ParseFirewallState(
      actual_port_rules, actual_blocked_hosts, test_input);

  EXPECT_EQ(expected_blocked_hosts.size(), actual_blocked_hosts.size());
  if (expected_blocked_hosts.size() == actual_blocked_hosts.size()) {
    EXPECT_EQ(*expected_blocked_hosts.begin(), *actual_blocked_hosts.begin());
  }

  EXPECT_EQ(expected_port_rules.size(), actual_port_rules.size());

  if (expected_port_rules.size() == actual_port_rules.size()) {
    auto it = expected_port_rules.begin();

    for (const auto& port_rule : actual_port_rules) {
      auto port_rule_description = GetPortRuleDescription(port_rule);
      const auto& expected_rule = *it;

      EXPECT_EQ(expected_rule, port_rule_description);
      it++;
    }
  }
}
} // namespace trailofbits
