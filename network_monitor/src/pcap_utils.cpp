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

#include "pcap_utils.h"

#include <osquery/logger/logger.h>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>

namespace trailofbits {
osquery::Status createPcap(PcapRef& ref,
                           const std::string& device_name,
                           int capture_buffer_size,
                           int packet_capture_timeout,
                           bool promiscuous_mode) {
  ref.reset();

  char error_message[PCAP_ERRBUF_SIZE] = {};

  auto ptr = pcap_create(device_name.c_str(), error_message);
  if (ptr == nullptr) {
    return osquery::Status::failure(error_message);
  }

  if (promiscuous_mode) {
    if (pcap_set_promisc(ptr, 1) != 0) {
      return osquery::Status::failure("Failed to enable the promiscuous mode");
    }

    LOG(WARNING) << "Promiscuous mode has been enabled";
  }

  if (pcap_set_timeout(ptr, packet_capture_timeout) != 0) {
    return osquery::Status::failure("Failed to set the capture timeout");
  }

  if (pcap_set_buffer_size(ptr, capture_buffer_size) != 0) {
    return osquery::Status::failure("Failed to set the capture buffer size");
  }

  if (pcap_activate(ptr) < 0) {
    return osquery::Status::failure("Failed to activate the pcap handle");
  }

  ref.reset(ptr);
  return osquery::Status(0);
}

void pcapRefDeleter(pcap_t* handle) {
  if (handle == nullptr) {
    return;
  }

  pcap_close(handle);
}

osquery::Status getNetworkDeviceInformation(NetworkDeviceInformation& dev_info,
                                            const std::string& device_name) {
  dev_info = {};

  pcap_if_t* interface_list = nullptr;
  char error_message[PCAP_ERRBUF_SIZE] = {};

  if (pcap_findalldevs(&interface_list, error_message) != 0) {
    return osquery::Status::failure(error_message);
  }

  if (interface_list == nullptr) {
    return osquery::Status::failure("No device found");
  }

  pcap_if_t* pcap_dev_info = nullptr;

  {
    auto it = interface_list;

    do {
      if (it->name == device_name) {
        pcap_dev_info = it;
        break;
      }

      it = it->next;
    } while (it != nullptr);
  }

  if (pcap_dev_info == nullptr) {
    return osquery::Status::failure("The specified device was not found");
  }

  dev_info.name = pcap_dev_info->name;
  dev_info.flags = pcap_dev_info->flags;

  if (pcap_dev_info->description != nullptr) {
    dev_info.description = pcap_dev_info->description;
  }

  for (auto it = pcap_dev_info->addresses; it != nullptr; it = it->next) {
    if (it->addr->sa_family != AF_INET && it->addr->sa_family != AF_INET6) {
      continue;
    }

    auto address_family = it->addr->sa_family;

    auto address_ptr =
        &reinterpret_cast<struct sockaddr_in*>(it->addr)->sin_addr;

    auto netmask_ptr =
        &reinterpret_cast<struct sockaddr_in*>(it->netmask)->sin_addr;

    char ip_address[INET6_ADDRSTRLEN] = {};
    if (inet_ntop(
            address_family, address_ptr, ip_address, sizeof(ip_address)) ==
        nullptr) {
      return osquery::Status::failure(
          "Failed to acquire the ip address for the specified interface");
    }

    char netmask[INET6_ADDRSTRLEN];
    if (inet_ntop(address_family, netmask_ptr, netmask, sizeof(netmask)) ==
        nullptr) {
      return osquery::Status::failure(
          "Failed to acquire the ip address for the specified interface");
    }

    NetworkAddress net_address = {ip_address, netmask};
    if (it->addr->sa_family == AF_INET) {
      dev_info.ipv4_address_list.push_back(std::move(net_address));
    } else if (it->addr->sa_family == AF_INET6) {
      dev_info.ipv6_address_list.push_back(std::move(net_address));
    }
  }

  pcap_freealldevs(interface_list);
  return osquery::Status(0);
}

osquery::Status waitForNewPackets(bool& timed_out,
                                  PcapRef& ref,
                                  std::size_t msecs) {
  timed_out = false;

  auto pcap_fd = pcap_get_selectable_fd(ref.get());
  if (pcap_fd == -1) {
    return osquery::Status::failure("Not supported on this platform");
  }

  pollfd fds[] = {{pcap_fd, POLLIN, 0}};

  int poll_status = ::poll(fds, 1, static_cast<int>(msecs));
  if (poll_status == 0) {
    timed_out = true;
    return osquery::Status(0);
  }

  if (poll_status < 0) {
    timed_out = true;

    if (errno != EINTR) {
      return osquery::Status::failure("poll() failed with error " +
                                      std::to_string(errno));
    } else {
      return osquery::Status(0);
    }
  }

  if ((fds[0].revents & POLLIN) == 0) {
    timed_out = true;
    return osquery::Status(0);
  }

  return osquery::Status(0);
}
} // namespace trailofbits
