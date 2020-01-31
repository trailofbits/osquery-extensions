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

#include "ntfsdirectoryindexentry.h"

#include <iomanip>
#include <sstream>

namespace trailofbits {
std::string NTFSDirectoryIndexEntry::getStringRep() const {
  std::stringstream output;
  output << "inode: " << this->mft_ref.inode << "\n"
         << "seq: " << this->mft_ref.sequence << "\n"
         << "entry_length: " << this->entry_length << "\n"
         << "name_length: " << this->name_length << "\n"
         << "flags: " << this->flags << "\n"
         << "filename: "
         << (name_length > 0 ? this->filename.filename : "(no name)") << "\n"
         << "child_vcn: " << this->child_vcn << "\n"
         << "slack_addr: " << this->slack_addr << "\n";

  return output.str();
}

bool NTFSDirectoryIndexEntry::valid() const {
  return filename.valid() && entry_length >= 0x52 && entry_length < 4096 &&
         flags < 4 && child_vcn < 4096 && name_length < 4096;
}
}