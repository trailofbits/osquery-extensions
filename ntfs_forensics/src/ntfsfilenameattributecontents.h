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

#include "ntfs_types.h"

namespace trailofbits {
struct NTFSFileNameAttributeContents final {
  NTFSMFTFileReference parent;
  NTFSTimestamp file_name_times;
  std::string filename;

  uint64_t allocated_size{0U};
  uint64_t real_size{0U};
  uint32_t flags{0U};
  uint8_t name_length{0U};

  bool valid() const;
};
} // namespace trailofbits