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

#include "ntfsfilenameattributecontents.h"

namespace trailofbits {
namespace {
uint32_t unixtimestamp(uint64_t ntdate) {
#define NSEC_BTWN_1601_1970 (uint64_t)(116444736000000000ULL)

  ntdate -= (uint64_t)NSEC_BTWN_1601_1970;
  ntdate /= (uint64_t)10000000;

  return (uint32_t)ntdate;
}
}

bool NTFSFileNameAttributeContents::valid() const {
  uint32_t unix_1990 = 631152000;
  uint32_t unix_2025 = 1735689600;

  return (unix_2025 > unixtimestamp(file_name_times.atime)) &&
         (unixtimestamp(file_name_times.atime) > unix_1990) &&
         (unix_2025 > unixtimestamp(file_name_times.btime)) &&
         (unixtimestamp(file_name_times.btime) > unix_1990) &&
         (unix_2025 > unixtimestamp(file_name_times.ctime)) &&
         (unixtimestamp(file_name_times.ctime) > unix_1990) &&
         (unix_2025 > unixtimestamp(file_name_times.mtime)) &&
         (unixtimestamp(file_name_times.mtime) > unix_1990);
}
}