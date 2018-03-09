#pragma once

#include <boost/noncopyable.hpp>

#include <cstdint>
#include <memory>
#include <string>

#include <trailofbits/istatus.h>

namespace trailofbits {
class IFirewall : private boost::noncopyable {
 public:
  enum class Detail {
    Undetermined,
    MemoryAllocationError,
    ExecError,
    InitializationError,
    CleanupError,
    QueryError,
    AlreadyExists,
    NotFound
  };

  using Status = IStatus<Detail>;

  enum class TrafficDirection { Inbound, Outbound };
  enum class Protocol { TCP, UDP };

  virtual ~IFirewall() = default;

  virtual Status addPortToBlacklist(std::uint16_t port,
                                    TrafficDirection direction,
                                    Protocol protocol) = 0;

  virtual Status removePortFromBlacklist(std::uint16_t port,
                                         TrafficDirection direction,
                                         Protocol protocol) = 0;

  virtual Status enumerateBlacklistedPorts(
      bool (*callback)(std::uint16_t port,
                       TrafficDirection direction,
                       Protocol protocol,
                       void* user_defined),
      void* user_defined) = 0;

  virtual Status addHostToBlacklist(const std::string& host) = 0;
  virtual Status removeHostFromBlacklist(const std::string& host) = 0;

  virtual Status enumerateBlacklistedHosts(
      bool (*callback)(const std::string& host, void* user_defined),
      void* user_defined) = 0;
};

IFirewall::Status CreateFirewallObject(std::unique_ptr<IFirewall>& obj);
} // namespace trailofbits
