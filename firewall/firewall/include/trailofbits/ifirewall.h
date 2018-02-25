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
  enum class State { Active, Pending, Error };

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
                       State state,
                       void* user_defined),
      void* user_defined) = 0;

  virtual Status addHostToBlacklist() = 0;
  virtual Status removeHostFromBlacklist() = 0;
  virtual Status enumerateBlacklistedHosts() const = 0;
};

IFirewall::Status CreateFirewallObject(std::unique_ptr<IFirewall>& obj);
} // namespace trailofbits
