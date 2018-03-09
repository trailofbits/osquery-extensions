#pragma once

#include <memory>
#include <set>

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
  struct PortRule final {
    std::uint16_t port;
    TrafficDirection direction;
    Protocol protocol;
  };

  Firewall();

  Status readFirewallState(std::vector<PortRule>& port_rules,
                           std::set<std::string>& host_rules);

  Status applyNewFirewallRules(const std::vector<PortRule>& port_rules,
                               const std::set<std::string>& host_rules);

  static Status enableFirewall(std::string& token);
  static Status disableFirewall(const std::string& token);

  static Status ReadAnchor(std::string& contents, const std::string& anchor);

  static Status ReadTable(std::string& contents,
                          const std::string& anchor,
                          const std::string& table);

  static Status ParsePortRulesFromAnchor(const std::string& contents,
                                         std::vector<PortRule>& port_rule_list);

  static void ParseTable(const std::string& contents,
                         std::set<std::string>& table);

  static bool IsHostBlacklistTableActive(const std::string& contents,
                                         const std::string& table);

  static std::string GenerateTable(const std::string& table_name,
                                   const std::set<std::string> blocked_hosts);

  static std::string GenerateHostRules(
      const std::string& table_name, const std::set<std::string> blocked_hosts);

  static std::string GeneratePortRules(const std::vector<PortRule>& rules);

  static std::string GenerateRules(const std::string& blocked_hosts_table_name,
                                   const std::set<std::string> blocked_hosts,
                                   const std::vector<PortRule>& port_rules);

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};

Firewall::Status CreateFirewallObject(std::unique_ptr<IFirewall>& obj);
} // namespace trailofbits
