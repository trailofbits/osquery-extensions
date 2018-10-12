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

#include "packet.h"

#include <boost/variant.hpp>

#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <pcap/dlt.h>

namespace trailofbits {
/// Private class data
struct Packet::PrivateData final {
  int link_type{0};
  std::time_t capture_timestamp{0};

  std::vector<std::uint8_t> packet_data;

  IPProtocol ip_protocol;
  boost::variant<iphdr, ip6_hdr> ip_header;

  Protocol protocol;
  boost::variant<udphdr, tcphdr> protocol_header;
};

Packet::Packet(int link_type,
               std::time_t capture_timestamp,
               std::vector<std::uint8_t> packet_data)
    : d(new PrivateData) {
  d->link_type = link_type;
  d->capture_timestamp = capture_timestamp;

  auto packet_ptr = packet_data.data();
  auto packet_end_ptr = packet_ptr + packet_data.size();

  int type = 0;
  if (link_type == DLT_IPV4) {
    type = ETH_P_IP;

  } else if (link_type == DLT_IPV6) {
    type = ETH_P_IPV6;

  } else if (link_type == DLT_EN10MB) {
    auto ptr = reinterpret_cast<const std::uint8_t*>(packet_data.data() +
                                                     ETH_HLEN - 2);
    if (ptr >= packet_end_ptr) {
      throw osquery::Status(1, "The packet seems to be broken");
    }

    auto& raw_type = *reinterpret_cast<const std::uint32_t*>(ptr);
    type = ntohs(raw_type);

    packet_ptr += ETH_HLEN;

  } else {
    throw osquery::Status(1, "Invalid link layer type specified");
  }

  int protocol = 0;
  if (type == ETH_P_IP) {
    if (packet_ptr + sizeof(iphdr) >= packet_end_ptr) {
      throw osquery::Status(1, "The packet seems to be broken");
    }

    const auto& header = *reinterpret_cast<const iphdr*>(packet_ptr);
    protocol = header.protocol;
    d->ip_protocol = IPProtocol::IPv4;
    d->ip_header = header;

    packet_ptr += (header.ihl * 4);

  } else if (type == ETH_P_IPV6) {
    if (packet_ptr + sizeof(ip6_hdr) >= packet_end_ptr) {
      throw osquery::Status(1, "The packet seems to be broken");
    }

    const auto& header = *reinterpret_cast<const ip6_hdr*>(packet_ptr);
    protocol = header.ip6_nxt;
    d->ip_protocol = IPProtocol::IPv6;
    d->ip_header = header;

    // The IPv6 header length is fixed
    packet_ptr += 40;

  } else {
    throw osquery::Status(1, "Invalid IP protocol");
  }

  if (protocol == IPPROTO_UDP) {
    d->protocol = Protocol::UDP;

    if (packet_ptr + sizeof(udphdr) >= packet_end_ptr) {
      throw osquery::Status(1, "The packet seems to be broken");
    }

    const auto& header = *reinterpret_cast<const udphdr*>(packet_ptr);
    d->protocol_header = header;

    packet_ptr += 8;

  } else if (protocol == IPPROTO_TCP) {
    d->protocol = Protocol::TCP;

    if (packet_ptr + sizeof(tcphdr) >= packet_end_ptr) {
      throw osquery::Status(1, "The packet seems to be broken");
    }

    const auto& header = *reinterpret_cast<const tcphdr*>(packet_ptr);
    d->protocol_header = header;

    packet_ptr += (header.doff * 4) + 1;

  } else {
    throw osquery::Status(1, "Invalid protocol");
  }

  d->packet_data.assign(packet_ptr, packet_end_ptr);
}

osquery::Status Packet::create(PacketRef& ref,
                               int link_type,
                               std::time_t capture_timestamp,
                               const std::vector<std::uint8_t>& packet_data) {
  ref.reset();

  try {
    auto ptr = new Packet(link_type, capture_timestamp, packet_data);
    ref.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

IPProtocol Packet::ipProtocol() const {
  return d->ip_protocol;
}

std::time_t Packet::timestamp() const {
  return d->capture_timestamp;
}

Protocol Packet::protocol() const {
  return d->protocol;
}

IPAddress Packet::sourceAddress() const {
  IPAddress output;

  output.ip_protocol = d->ip_protocol;

  switch (d->ip_protocol) {
  case IPProtocol::IPv4: {
    const auto& header = boost::get<iphdr>(d->ip_header);
    output.address = header.saddr;

    break;
  }

  case IPProtocol::IPv6: {
    const auto& header = boost::get<ip6_hdr>(d->ip_header);
    output.address = header.ip6_src;

    break;
  }
  }

  return output;
}

IPAddress Packet::destinationAddress() const {
  IPAddress output;

  output.ip_protocol = d->ip_protocol;

  switch (d->ip_protocol) {
  case IPProtocol::IPv4: {
    const auto& header = boost::get<iphdr>(d->ip_header);
    output.address = header.daddr;

    break;
  }

  case IPProtocol::IPv6: {
    const auto& header = boost::get<ip6_hdr>(d->ip_header);
    output.address = header.ip6_dst;

    break;
  }
  }

  return output;
}

std::uint16_t Packet::sourcePort() const {
  switch (d->protocol) {
  case Protocol::TCP: {
    const auto& header = boost::get<tcphdr>(d->protocol_header);
    return ntohs(header.source);
  }

  case Protocol::UDP: {
    const auto& header = boost::get<udphdr>(d->protocol_header);
    return ntohs(header.source);
  }
  }
}

std::uint16_t Packet::destinationPort() const {
  switch (d->protocol) {
  case Protocol::TCP: {
    const auto& header = boost::get<tcphdr>(d->protocol_header);
    return ntohs(header.dest);
  }

  case Protocol::UDP: {
    const auto& header = boost::get<udphdr>(d->protocol_header);
    return ntohs(header.dest);
  }
  }
}

const std::vector<std::uint8_t>& Packet::data() const {
  return d->packet_data;
}

bool operator==(const IPAddress& l, const IPAddress& r) {
  if (l.ip_protocol != r.ip_protocol) {
    return false;
  }

  if (l.ip_protocol == IPProtocol::IPv4) {
    auto first_address = boost::get<u_int32_t>(l.address);
    auto second_address = boost::get<u_int32_t>(r.address);
    return first_address == second_address;

  } else {
    auto first_address = boost::get<in6_addr>(l.address);
    auto second_address = boost::get<in6_addr>(r.address);

    auto res = std::memcmp(first_address.s6_addr, second_address.s6_addr, 16U);
    return res == 0;
  }
}

bool operator!=(const IPAddress& l, const IPAddress& r) {
  return !(l == r);
}
} // namespace trailofbits
