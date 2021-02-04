#pragma once

#include <memory>
#include <set>
#include <sstream>
#include <vector>

#include <boost/variant.hpp>

#include <trailofbits/ifirewall.h>

namespace trailofbits {
class Firewall final : public IFirewall {
 public:
  static Status create(std::unique_ptr<IFirewall>& obj);
  virtual ~Firewall();

  virtual Status addPortToDenylist(std::uint16_t port,
                                    TrafficDirection direction,
                                    Protocol protocol) override;

  virtual Status removePortFromDenylist(std::uint16_t port,
                                         TrafficDirection direction,
                                         Protocol protocol) override;

  virtual Status enumerateDenylistedPorts(
      bool (*callback)(std::uint16_t port,
                       TrafficDirection direction,
                       Protocol protocol,
                       void* user_defined),
      void* user_defined) override;

  virtual Status addHostToDenylist(const std::string& host) override;
  virtual Status removeHostFromDenylist(const std::string& host) override;

  virtual Status enumerateDenylistedHosts(
      bool (*callback)(const std::string& host, void* user_defined),
      void* user_defined) override;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  Firewall();

  static Status ReadFirewallState(std::string& state);
  static void Firewall::getHostBlockRuleNames(
      const std::string& state,
      const std::string& host,
      std::set<std::string>& rule_names);

 public:
  struct PortRule final {
    std::uint16_t port;
    TrafficDirection direction;
    Protocol protocol;
    std::string name;
  };

  struct IPRule final {
    TrafficDirection direction;
    std::string address;
  };

  using Rule = boost::variant<PortRule, IPRule>;

  typedef std::set<std::string> HostSet;

  static void ParseFirewallState(std::vector<PortRule>& port_rules,
                                 HostSet& blocked_hosts,
                                 const std::string& state);
  static bool ParseFirewallRuleBlock(std::stringstream& stream,
                                     const std::string& rule_name,
                                     Rule& rule);
};

Firewall::Status CreateFirewallObject(std::unique_ptr<IFirewall>& obj);
} // namespace trailofbits
