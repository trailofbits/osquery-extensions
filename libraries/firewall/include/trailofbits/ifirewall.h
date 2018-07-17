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
