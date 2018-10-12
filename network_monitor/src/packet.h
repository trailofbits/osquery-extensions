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
#include <vector>

#include <osquery/status.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

namespace trailofbits {
class Packet;

/// A reference to a Packet object
using PacketRef = std::shared_ptr<Packet>;

/// Protocol type
enum class Protocol { TCP, UDP };

/// IP Protocol type
enum class IPProtocol { IPv4, IPv6 };

/// IP address
struct IPAddress final {
  /// IP protocol type; either IPv4 or IPv6
  IPProtocol ip_protocol;

  /// The ip address; use boost::get<> to acquire it
  boost::variant<u_int32_t, in6_addr> address;
};

/// Allow the user to easily compare IPAddress structures
bool operator==(const IPAddress& l, const IPAddress& r);

/// Allow the user to easily compare IPAddress structures
bool operator!=(const IPAddress& l, const IPAddress& r);

/// A packet object
class Packet final {
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// Private constructor; use ::create() instead
  Packet(int link_type,
         std::time_t capture_timestamp,
         std::vector<std::uint8_t> packet_data);

 public:
  /// Crates a new packet object from the given packet data
  static osquery::Status create(PacketRef& ref,
                                int link_type,
                                std::time_t capture_timestamp,
                                const std::vector<std::uint8_t>& packet_data);

  /// Returns the IP protocol
  IPProtocol ipProtocol() const;

  /// Eithert TCP or UDP
  Protocol protocol() const;

  /// Returns the timestamp
  std::time_t timestamp() const;

  /// Returns the source address
  IPAddress sourceAddress() const;

  /// Returns the destination address
  IPAddress destinationAddress() const;

  /// Returns the source port
  std::uint16_t sourcePort() const;

  /// Returns the destination port
  std::uint16_t destinationPort() const;

  /// Returns the packet data
  const std::vector<std::uint8_t>& data() const;
};
} // namespace trailofbits
