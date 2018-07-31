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

#include <list>
#include <string>

#include <tsk/libtsk.h>

#include "ntfs_types.h"
#include "ntfsfilenameattributecontents.h"

namespace trailofbits {
struct NTFSDirectoryIndexEntry final {
  NTFSMFTFileReference mft_ref;
  NTFSFileNameAttributeContents filename;

  uint16_t entry_length{0U};
  uint16_t name_length{0U};
  uint32_t flags{0U};
  uint64_t child_vcn{0U};
  uint32_t slack_addr{0U};

  std::string getStringRep() const;
  bool valid() const;
};

using DirEntryList = std::list<NTFSDirectoryIndexEntry>;
}
