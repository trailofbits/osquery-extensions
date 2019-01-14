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

#include <gtest/gtest.h>

#include "utils.h"

namespace trailofbits {
TEST(IptablesUtilsTests, TestGetTableNames) {
  const auto& iptablesNames = getIptablesNames();

  for (const auto& table : iptablesNames) {
    EXPECT_TRUE(table.size() > 0);
  }

  const auto& ip6tablesNames = getIp6tablesNames();

  for (const auto& table : ip6tablesNames) {
    EXPECT_TRUE(table.size() > 0);
  }
}

TEST(IptablesUtilsTests, TestIpAsString) {
  in_addr in4 = {};
  in6_addr in6 = {};

  sockaddr_in addr4;
  addr4.sin_addr = in4;
  addr4.sin_family = AF_INET;
  addr4.sin_port = 0;

  sockaddr_in6 addr6;
  addr6.sin6_addr = in6;
  addr6.sin6_family = AF_INET6;
  addr6.sin6_port = 0;
  addr6.sin6_scope_id = 0;

  std::string ip_string = ipAsString(reinterpret_cast<sockaddr*>(&addr4));
  EXPECT_EQ("0.0.0.0", ip_string);

  ip_string = ipAsString(reinterpret_cast<sockaddr*>(&addr6));
  EXPECT_EQ("::", ip_string);

  ip_string = ipAsString(&in4);
  EXPECT_EQ("0.0.0.0", ip_string);

  ip_string = ipAsString(&in6);
  EXPECT_EQ("::", ip_string);

  in4.s_addr = -1;
  ip_string = ipAsString(&in4);
  EXPECT_EQ("255.255.255.255", ip_string);

  unsigned char junk[16] = {
      255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0};
  memcpy(&in6.s6_addr, junk, sizeof(junk));
  ip_string = ipAsString(&in6);
  EXPECT_EQ("ffff:0:ffff:0:ffff:0:ffff:0", ip_string);
}

TEST(IptablesUtilsTests, TestIpMaskAsString) {
  in_addr in4 = {};
  in6_addr in6 = {};

  std::string mask_string = ipMaskAsString(&in4);
  EXPECT_EQ("0.0.0.0", mask_string);

  mask_string = ipMaskAsString(&in6);
  EXPECT_EQ("0000:0000:0000:0000:0000:0000:0000:0000", mask_string);
}

TEST(IptablesUtilsTests, TestIfaceMaskAsString) {
  unsigned char mask[IFNAMSIZ] = {};
  auto mask_string = ifaceMaskAsString(mask);
  EXPECT_EQ("", mask_string);

  unsigned char mask2[IFNAMSIZ] = {0xFF, 0xFF, 0xFF, 0xFF, 0};
  mask_string = ifaceMaskAsString(mask2);
  EXPECT_EQ("FFFFFFFF", mask_string);
}
} // namespace trailofbits
