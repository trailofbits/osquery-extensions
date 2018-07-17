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

#include "hostblacklist.h"

#include <sstream>

#include <gtest/gtest.h>

namespace trailofbits {
#ifdef LINUX
const std::string ipv6_localhost = "ip6-localhost";
#elif APPLE
const std::string ipv6_localhost = "localhost";
#else
const std::string ipv6_localhost = "localhost";
#endif

TEST(HostBlacklistTests, DomainResolution) {
  std::string ipv4_address;
  auto status =
      HostBlacklistTable::DomainToAddress(ipv4_address, "localhost", true);

  EXPECT_TRUE(status.ok());
  if (status.ok()) {
    EXPECT_EQ(ipv4_address, "127.0.0.1");
  }

  // ipv6 may not be available here
  std::string ipv6_address;
  status =
      HostBlacklistTable::DomainToAddress(ipv6_address, "localhost", false);
  if (status.ok()) {
    EXPECT_EQ(ipv6_address, "::1");
  }
}

TEST(HostBlacklistTests, ReverseLookup) {
  std::string domain;
  auto status = HostBlacklistTable::AddressToDomain(domain, "127.0.0.1");

  EXPECT_TRUE(status.ok());
  if (status.ok()) {
    EXPECT_EQ(domain, "localhost");
  }

  status = HostBlacklistTable::AddressToDomain(domain, "::1");

  EXPECT_TRUE(status.ok());
  if (status.ok()) {
    EXPECT_EQ(domain, ipv6_localhost);
  }
}
} // namespace trailofbits
