/*
 * Copyright (c) 2019-present Trail of Bits, Inc.
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

#include "socketeventssubscriber.h"

#include <iomanip>

#include <asm/unistd_64.h>
#include <linux/socket.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace trailofbits {
namespace {
// clang-format off
const std::unordered_map<std::uint64_t, std::string> kSyscallNameTable = {
  { __NR_bind, "bind" },
  { __NR_connect, "connect" }

  //{ __NR_listen, "listen" },
  //{ __NR_accept, "accept" },
  //{ __NR_accept4, "accept4" }
};
// clang-format on

// clang-format off
const std::unordered_map<int, std::string> kProtocolFamilyNameTable = {
  { PF_UNSPEC, "UNSPEC" },
  { PF_LOCAL, "LOCAL" },
  { PF_UNIX, "UNIX" },
  { PF_FILE, "FILE" },
  { PF_INET, "INET" },
  { PF_AX25, "AX25" },
  { PF_IPX, "IPX" },
  { PF_APPLETALK, "APPLETALK" },
  { PF_NETROM, "NETROM" },
  { PF_BRIDGE, "BRIDGE" },
  { PF_ATMPVC, "ATMPVC" },
  { PF_X25, "X25" },
  { PF_INET6, "INET6" },
  { PF_ROSE, "ROSE" },
  { PF_DECnet, "DECnet" },
  { PF_NETBEUI, "NETBEUI" },
  { PF_SECURITY, "SECURITY" },
  { PF_KEY, "KEY" },
  { PF_NETLINK, "NETLINK" },
  { PF_ROUTE, "ROUTE" },
  { PF_PACKET, "PACKET" },
  { PF_ASH, "ASH" },
  { PF_ECONET, "ECONET" },
  { PF_ATMSVC, "ATMSVC" },
  { PF_RDS, "RDS" },
  { PF_SNA, "SNA" },
  { PF_IRDA, "IRDA" },
  { PF_PPPOX, "PPPOX" },
  { PF_WANPIPE, "WANPIPE" },
  { PF_LLC, "LLC" },
/*  { PF_IB, "IB" },
  { PF_MPLS, "MPLS" },
  { PF_CAN, "CAN" },
  { PF_TIPC, "TIPC" },
  { PF_BLUETOOTH, "BLUETOOTH" },
  { PF_IUCV, "IUCV" },
  { PF_RXRPC, "RXRPC" },
  { PF_ISDN, "ISDN" },
  { PF_PHONET, "PHONET" },
  { PF_IEEE802154, "IEEE802154" },
  { PF_CAIF, "CAIF" },
  { PF_ALG, "ALG" },
  { PF_NFC, "NFC" },
  { PF_VSOCK, "VSOCK" },
  { PF_KCM, "KCM" },
  { PF_QIPCRTR, "QIPCRTR" },
  { PF_SMC, "SMC" },
  { PF_MAX, "MAX" }*/
};
// clang-format on

// clang-format off
const std::unordered_map<int, std::string> kProtocolNameTable = {
  { IPPROTO_IP, "IPPROTO_TCP" },
  { IPPROTO_ICMP, "IPPROTO_ICMP" },
  { IPPROTO_IGMP, "IPPROTO_IGMP" },
  { IPPROTO_IPIP, "IPPROTO_IPIP" },
  { IPPROTO_TCP, "IPPROTO_TCP" },
  { IPPROTO_EGP, "IPPROTO_EGP" },
  { IPPROTO_PUP, "IPPROTO_PUP" },
  { IPPROTO_UDP, "IPPROTO_UDP" },
  { IPPROTO_IDP, "IPPROTO_IDP" },
  { IPPROTO_TP, "IPPROTO_TP" },
  { IPPROTO_DCCP, "IPPROTO_DCCP" },
  { IPPROTO_IPV6, "IPPROTO_IPV6" },
  { IPPROTO_RSVP, "IPPROTO_RSVP" },
  { IPPROTO_GRE, "IPPROTO_GRE" },
  { IPPROTO_ESP, "IPPROTO_ESP" },
  { IPPROTO_AH, "IPPROTO_AH" },
  { IPPROTO_MTP, "IPPROTO_MTP" },
  { IPPROTO_ENCAP, "IPPROTO_ENCAP" },
  { IPPROTO_PIM, "IPPROTO_PIM" },
  { IPPROTO_COMP, "IPPROTO_COMP" },
  { IPPROTO_SCTP, "IPPROTO_SCTP" },
  { IPPROTO_UDPLITE, "IPPROTO_UDPLITE" }
};
// clang-format on

// clang-format off
const std::unordered_map<int, std::string> kSocketTypeName = {
  { SOCK_STREAM, "SOCK_STREAM" },
  { SOCK_DGRAM, "SOCK_DGRAM" },
  { SOCK_SEQPACKET, "SOCK_SEQPACKET" },
  { SOCK_RAW, "SOCK_RAW" },
  { SOCK_RDM, "SOCK_RDM" },
  { SOCK_PACKET, "SOCK_PACKET" }
};
// clang-format on

const std::string& getSystemCallName(int system_call_nr) {
  static const std::string kUnknownSystemCallName{"Unknown"};

  auto name_it = kSyscallNameTable.find(system_call_nr);
  if (name_it == kSyscallNameTable.end()) {
    return kUnknownSystemCallName;
  }

  return name_it->second;
}

const std::string& getProtocolFamilyName(int family) {
  static const std::string kUnknownProtocolFamilyName{"Unknown"};

  auto name_it = kProtocolFamilyNameTable.find(family);
  if (name_it == kProtocolFamilyNameTable.end()) {
    return kUnknownProtocolFamilyName;
  }

  return name_it->second;
}

const std::string& getProtocolName(std::int64_t protocol) {
  static const std::string kUnknownProtocolName{"Unknown"};

  auto name_it = kProtocolNameTable.find(protocol);
  if (name_it == kProtocolNameTable.end()) {
    LOG(ERROR) << "UNKNOWN PROTOCOL: " << protocol;
    return kUnknownProtocolName;
  }

  return name_it->second;
}

const std::string& getSocketTypeName(std::int64_t type) {
  static const std::string kUnknownSocketTypeName{"Unknown"};

  auto name_it = kSocketTypeName.find(type);
  if (name_it == kSocketTypeName.end()) {
    LOG(ERROR) << "UNKNOWN SOCKET TYPE: " << type;
    return kUnknownSocketTypeName;
  }

  return name_it->second;
}

std::string getAddressFromSockaddr(const struct sockaddr_in& sockaddr) {
  std::string address;

  address = std::to_string(sockaddr.sin_addr.s_addr & 0xFF) + ".";
  address += std::to_string((sockaddr.sin_addr.s_addr >> 8) & 0xFF) + ".";
  address += std::to_string((sockaddr.sin_addr.s_addr >> 16) & 0xFF) + ".";
  address += std::to_string((sockaddr.sin_addr.s_addr >> 24) & 0xFF);

  return address;
}

std::string getAddressFromSockaddr(const struct sockaddr_in6& sockaddr) {
  std::stringstream buffer;

  for (auto i = 0U; i < 16U; i++) {
    if (!buffer.str().empty()) {
      buffer << ":";
    }

    buffer << std::setfill('0') << std::setw(2) << std::hex
           << static_cast<int>(sockaddr.sin6_addr.__in6_u.__u6_addr8[i]);
  }

  return buffer.str();
}

osquery::Status getAddressFromRawSockaddr(
    std::string& address,
    int& protocol_family,
    std::uint16_t& port,
    const std::vector<std::uint8_t>& buffer,
    std::size_t buffer_length) {
  address = {};
  protocol_family = 0;
  port = 0U;

  std::string output_address;
  int output_protocol_family = 0;
  std::uint16_t output_port;

  osquery::Status status;

  if (buffer_length == sizeof(struct sockaddr_in)) {
    struct sockaddr_in sockaddr = {};
    std::memcpy(&sockaddr, buffer.data(), buffer_length);

    output_address = getAddressFromSockaddr(sockaddr);
    output_protocol_family = sockaddr.sin_family;
    output_port = htons(sockaddr.sin_port);

    status = osquery::Status(0);

  } else if (buffer_length == sizeof(struct sockaddr_in6)) {
    struct sockaddr_in6 sockaddr = {};
    std::memcpy(&sockaddr, buffer.data(), buffer_length);

    output_address = getAddressFromSockaddr(sockaddr);
    output_protocol_family = sockaddr.sin6_family;
    output_port = htons(sockaddr.sin6_port);

    status = osquery::Status(0);

  } else {
    status = osquery::Status::failure("Unrecognized sockaddr structure type");
  }

  if (!status.ok()) {
    return status;
  }

  address = std::move(output_address);
  protocol_family = output_protocol_family;
  port = output_port;

  return osquery::Status(0);
}
} // namespace

// clang-format off
BEGIN_TABLE(ebpf_socket_events)
  TABLE_COLUMN(timestamp, osquery::TEXT_TYPE)
  TABLE_COLUMN(ppid, osquery::TEXT_TYPE)
  TABLE_COLUMN(pid, osquery::TEXT_TYPE)
  TABLE_COLUMN(tid, osquery::TEXT_TYPE)
  TABLE_COLUMN(uid, osquery::TEXT_TYPE)
  TABLE_COLUMN(gid, osquery::TEXT_TYPE)
  TABLE_COLUMN(event, osquery::TEXT_TYPE)
  TABLE_COLUMN(exit_code, osquery::TEXT_TYPE)
  TABLE_COLUMN(blocking, osquery::TEXT_TYPE)
  TABLE_COLUMN(family, osquery::TEXT_TYPE)
  TABLE_COLUMN(type, osquery::TEXT_TYPE)
  TABLE_COLUMN(protocol, osquery::TEXT_TYPE)
  TABLE_COLUMN(local_address, osquery::TEXT_TYPE)
  TABLE_COLUMN(remote_address, osquery::TEXT_TYPE)
  TABLE_COLUMN(local_port, osquery::TEXT_TYPE)
  TABLE_COLUMN(remote_port, osquery::TEXT_TYPE)
  TABLE_COLUMN(docker_container_id, osquery::TEXT_TYPE)
END_TABLE(ebpf_socket_events)
// clang-format on

struct SocketEventsSubscriber::PrivateData final {};

SocketEventsSubscriber::SocketEventsSubscriber() : d(new PrivateData) {}

osquery::Status SocketEventsSubscriber::create(
    IEventSubscriberRef& subscriber) {
  try {
    auto ptr = new SocketEventsSubscriber();
    subscriber.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

SocketEventsSubscriber::~SocketEventsSubscriber() {}

osquery::Status SocketEventsSubscriber::initialize() noexcept {
  return osquery::Status(0);
}

void SocketEventsSubscriber::release() noexcept {}

osquery::Status SocketEventsSubscriber::configure(
    ProcessEventsPublisher::SubscriptionContextRef subscription_context,
    const json11::Json&) noexcept {
  subscription_context->system_call_filter.insert(__NR_bind);
  subscription_context->system_call_filter.insert(__NR_connect);
  // subscription_context->system_call_filter.insert(__NR_listen);
  // subscription_context->system_call_filter.insert(__NR_accept);
  // subscription_context->system_call_filter.insert(__NR_accept4);

  return osquery::Status(0);
}

osquery::Status SocketEventsSubscriber::callback(
    osquery::QueryData& new_data,
    ProcessEventsPublisher::SubscriptionContextRef subscription_context,
    ProcessEventsPublisher::EventContextRef event_context) {
  new_data = {};

  for (const auto& event : event_context->probe_event_list) {
    osquery::Row row = {};
    row["timestamp"] = std::to_string(event.timestamp / 1000U);
    row["ppid"] = std::to_string(event.parent_tgid);
    row["pid"] = std::to_string(event.tgid);
    row["tid"] = std::to_string(event.pid);
    row["uid"] = std::to_string(event.uid);
    row["gid"] = std::to_string(event.gid);
    row["event"] = getSystemCallName(event.function_identifier);

    std::string docker_container_id = {};
    auto status =
        getProbeEventField(docker_container_id, event, "docker_container_id");
    if (!status.ok()) {
      row["docker_container_id"] = "";
    } else {
      row["docker_container_id"] = docker_container_id;
    }

    std::string exit_code = {};
    if (event.exit_code) {
      exit_code = std::to_string(event.exit_code.get());
    }

    row["exit_code"] = exit_code;

    std::int64_t protocol = 0;
    status = getProbeEventField(protocol, event, "protocol");
    if (!status.ok()) {
      row["protocol"] = "";
    } else {
      row["protocol"] = getProtocolName(protocol);
    }

    std::int64_t type = 0;
    status = getProbeEventField(type, event, "type");
    if (!status.ok()) {
      row["type"] = "";
    } else {
      row["type"] = getSocketTypeName(type);
    }

    std::int64_t blocking = 0;
    status = getProbeEventField(blocking, event, "blocking");
    if (!status.ok()) {
      row["blocking"] = "";
    } else {
      row["blocking"] = blocking == 0 ? "false" : "true";
    }

    std::string sockaddr_field_name;
    bool is_remote_address = false;

    if (event.function_identifier == __NR_bind) {
      is_remote_address = false;
      sockaddr_field_name = "umyaddr";

    } else if (event.function_identifier == __NR_connect) {
      is_remote_address = true;
      sockaddr_field_name = "uservaddr";

    } else {
      continue;
    }

    std::vector<std::uint8_t> sockaddr_data = {};
    status = getProbeEventField(sockaddr_data, event, sockaddr_field_name);
    if (!status.ok()) {
      LOG(ERROR) << status.getMessage();
      continue;
    }

    std::size_t addrlen = 0U;

    {
      std::int64_t temp_addrlen = {};
      status = getProbeEventField(temp_addrlen, event, "addrlen");
      if (!status.ok()) {
        LOG(ERROR) << status.getMessage();
        continue;
      }

      addrlen = static_cast<std::size_t>(temp_addrlen);
    }

    if (addrlen > sockaddr_data.size()) {
      VLOG(1) << "Invalid sockaddr structure length specified";
      continue;
    }

    std::string address;
    int protocol_family = 0;
    std::uint16_t port = 0;

    status = getAddressFromRawSockaddr(
        address, protocol_family, port, sockaddr_data, addrlen);
    if (!status.ok()) {
      VLOG(1) << status.getMessage();
      continue;
    }

    row["family"] = getProtocolFamilyName(protocol_family);

    if (is_remote_address) {
      row["local_address"] = "";
      row["local_port"] = "";

      row["remote_address"] = address;
      row["remote_port"] = std::to_string(port);

    } else {
      row["local_address"] = address;
      row["local_port"] = std::to_string(port);

      row["remote_address"] = "";
      row["remote_port"] = "";
    }

    new_data.push_back(std::move(row));
  }

  return osquery::Status(0);
}
} // namespace trailofbits
