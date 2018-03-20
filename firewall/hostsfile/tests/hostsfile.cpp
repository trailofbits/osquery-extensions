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

#include "hostsfile.h"

#include <sstream>

#include <gtest/gtest.h>

namespace trailofbits {
TEST(HostsFileTests, ParseHostsFileLine) {
  std::vector<std::string> test_input = {
      "# test",
      "1.2.3.4              temp # this is a comment!",
      "5.6.7.8       test1 test2 test3 test4",
      "",
      "9.10.11.12\t\ttest5"};

  std::vector<std::string> expected_output = {
      "1.2.3.4: temp",
      "5.6.7.8: test1, test2, test3, test4",
      "9.10.11.12: test5"};

  std::vector<std::string> actual_output;

  for (const auto& line : test_input) {
    std::string address;
    std::set<std::string> domain_list;

    if (HostsFile::ParseHostsFileLine(address, domain_list, line)) {
      std::stringstream stream;
      stream << address << ": ";

      for (auto it = domain_list.begin(); it != domain_list.end(); it++) {
        const auto& domain = *it;

        stream << domain;
        if (std::next(it, 1) != domain_list.end()) {
          stream << ", ";
        }
      }

      actual_output.push_back(stream.str());
    }
  }

  EXPECT_EQ(expected_output.size(), actual_output.size());

  for (auto i = 0U; i < expected_output.size(); i++) {
    EXPECT_EQ(expected_output.at(i), actual_output.at(i));
  }
}
} // namespace trailofbits
