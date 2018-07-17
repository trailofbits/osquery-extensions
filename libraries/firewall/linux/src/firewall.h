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

#pragma once

#include <memory>
#include <set>

#include <boost/variant.hpp>

#include <trailofbits/ifirewall.h>

namespace trailofbits {
class Firewall final : public IFirewall {
 public:
  static Status create(std::unique_ptr<IFirewall>& obj);
  virtual ~Firewall();

  virtual Status addPortToBlacklist(std::uint16_t port,
                                    TrafficDirection direction,
                                    Protocol protocol) override;

  virtual Status removePortFromBlacklist(std::uint16_t port,
                                         TrafficDirection direction,
                                         Protocol protocol) override;

  virtual Status enumerateBlacklistedPorts(
      bool (*callback)(std::uint16_t port,
                       TrafficDirection direction,
                       Protocol protocol,
                       void* user_defined),
      void* user_defined) override;

  virtual Status addHostToBlacklist(const std::string& host) override;
  virtual Status removeHostFromBlacklist(const std::string& host) override;

  virtual Status enumerateBlacklistedHosts(
      bool (*callback)(const std::string& host, void* user_defined),
      void* user_defined) override;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  Firewall();

  static Status ReadFirewallState(std::string& state);

 public:
  struct PortRule final {
    std::uint16_t port;
    TrafficDirection direction;
    Protocol protocol;
  };

  struct IPRule final {
    TrafficDirection direction;
    std::string address;
  };

  using Rule = boost::variant<PortRule, IPRule>;

  static void ParseFirewallState(std::vector<PortRule>& port_rules,
                                 std::set<std::string>& blocked_hosts,
                                 const std::string& state);

  static bool ParseFirewallStateLine(Rule& rule, const std::string& line);
};

Firewall::Status CreateFirewallObject(std::unique_ptr<IFirewall>& obj);
} // namespace trailofbits
