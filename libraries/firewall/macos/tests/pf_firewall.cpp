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
TEST(PfFirewallTests, ParsePortRulesFromAnchor) {
  // clang-format off
  const auto test_input =
    "block drop out quick proto tcp from any to any port = 11\n"
    "block drop in quick proto tcp from any to any port = 22\n"
    "block drop quick proto udp from any to any port = 33\n"
    "invalid line here\n";
  // clang-format on

  const std::vector<std::string> expected_output = {"Port 11/tcp (out)\n",
                                                    "Port 22/tcp (in)\n",
                                                    "Port 33/udp (in)\n",
                                                    "Port 33/udp (out)\n"};

  std::vector<Firewall::PortRule> port_rule_list;
  Firewall::ParsePortRulesFromAnchor(test_input, port_rule_list);

  EXPECT_EQ(port_rule_list.size(), 4U);

  std::vector<std::string> actual_output;
  for (const auto& rule : port_rule_list) {
    std::stringstream stream;
    stream << "Port " << rule.port << "/";

    if (rule.protocol == IFirewall::Protocol::UDP) {
      stream << "udp";
    } else {
      stream << "tcp";
    }
    stream << " (";

    if (rule.direction == IFirewall::TrafficDirection::Outbound) {
      stream << "out";
    } else {
      stream << "in";
    }
    stream << ")\n";

    actual_output.push_back(stream.str());
  }

  EXPECT_EQ(actual_output.size(), expected_output.size());

  for (auto i = 0U; i < actual_output.size(); i++) {
    EXPECT_EQ(actual_output.at(i), expected_output.at(i));
  }
}

TEST(PfFirewallTests, ParseTable) {
  // pfctl is not really this unreliable; IPs are always one per line, with
  // two spaces at the start

  // clang-format off
  const auto test_input =
    "         1.2.3.4   \n"
    "\t\t5.6.7.8\t\n"
    "127.0.0.1\n";
  // clang-format on

  const std::set<std::string> expected_output = {
      "1.2.3.4", "127.0.0.1", "5.6.7.8"};

  std::set<std::string> actual_output;
  Firewall::ParseTable(test_input, actual_output);

  EXPECT_TRUE(actual_output == expected_output);
}

TEST(PfFirewallTests, GenerateTable) {
  const std::set<std::string> blocked_hosts = {
      "1.2.3.4", "4.5.6.7", "8.9.10.11"};

  const std::string table_name = "test_table";
  const std::string expected_output =
      "table <test_table> persist { 1.2.3.4, 4.5.6.7, 8.9.10.11 }\n";

  auto actual_output = Firewall::GenerateTable(table_name, blocked_hosts);
  EXPECT_EQ(actual_output, expected_output);
}

TEST(PfFirewallTests, GenerateHostRules) {
  const std::set<std::string> blocked_hosts = {
      "1.2.3.4", "4.5.6.7", "8.9.10.11"};

  const std::string table_name = "test_table";

  // clang-format off
  const std::string expected_output =
    "table <test_table> persist { 1.2.3.4, 4.5.6.7, 8.9.10.11 }\n"
    "block drop from <test_table> to any\n"
    "block drop from any to <test_table>\n";
  // clang-format on

  auto actual_output = Firewall::GenerateHostRules(table_name, blocked_hosts);
  EXPECT_EQ(actual_output, expected_output);
}

TEST(PfFirewallTests, GeneratePortRules) {
  const std::vector<Firewall::PortRule> test_input = {
      {1, IFirewall::TrafficDirection::Inbound, IFirewall::Protocol::TCP},
      {2, IFirewall::TrafficDirection::Inbound, IFirewall::Protocol::UDP},
      {3, IFirewall::TrafficDirection::Inbound, IFirewall::Protocol::TCP},
      {4, IFirewall::TrafficDirection::Inbound, IFirewall::Protocol::UDP},
      {5, IFirewall::TrafficDirection::Inbound, IFirewall::Protocol::TCP},
      {6, IFirewall::TrafficDirection::Outbound, IFirewall::Protocol::UDP},
      {7, IFirewall::TrafficDirection::Outbound, IFirewall::Protocol::TCP},
      {8, IFirewall::TrafficDirection::Outbound, IFirewall::Protocol::UDP},
      {9, IFirewall::TrafficDirection::Outbound, IFirewall::Protocol::TCP},
      {10, IFirewall::TrafficDirection::Outbound, IFirewall::Protocol::UDP}};

  // clang-format off
  const std::string expected_output =
    "block drop in quick proto tcp to any port 1\n"
    "block drop in quick proto udp to any port 2\n"
    "block drop in quick proto tcp to any port 3\n"
    "block drop in quick proto udp to any port 4\n"
    "block drop in quick proto tcp to any port 5\n"
    "block drop out quick proto udp to any port 6\n"
    "block drop out quick proto tcp to any port 7\n"
    "block drop out quick proto udp to any port 8\n"
    "block drop out quick proto tcp to any port 9\n"
    "block drop out quick proto udp to any port 10\n";
  // clang-format on

  auto actual_output = Firewall::GeneratePortRules(test_input);
  EXPECT_EQ(actual_output, expected_output);
}

TEST(PfFirewallTests, GenerateRules) {
  const std::vector<Firewall::PortRule> port_rules = {
      {1, IFirewall::TrafficDirection::Inbound, IFirewall::Protocol::UDP},
      {2, IFirewall::TrafficDirection::Outbound, IFirewall::Protocol::UDP},
      {3, IFirewall::TrafficDirection::Inbound, IFirewall::Protocol::TCP},
      {4, IFirewall::TrafficDirection::Outbound, IFirewall::Protocol::TCP}};

  const std::set<std::string> blocked_hosts = {
      "1.2.3.4", "4.5.6.7", "8.9.10.11"};

  const std::string table_name = "test_table";

  // clang-format off
  const std::string expected_output =
    "table <test_table> persist { 1.2.3.4, 4.5.6.7, 8.9.10.11 }\n"
    "block drop from <test_table> to any\n"
    "block drop from any to <test_table>\n"
    "block drop in quick proto udp to any port 1\n"
    "block drop out quick proto udp to any port 2\n"
    "block drop in quick proto tcp to any port 3\n"
    "block drop out quick proto tcp to any port 4\n";
  // clang-format on

  auto actual_output =
      Firewall::GenerateRules(table_name, blocked_hosts, port_rules);
  EXPECT_EQ(actual_output, expected_output);
}
} // namespace trailofbits
