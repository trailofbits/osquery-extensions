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

#include <iomanip>
#include <sstream>

#include <tsk/libtsk.h>

#include "fileinfo.h"

namespace trailofbits {
FileInfo::FileInfo()
    : type(0),
      active(0),
      flag_val(0),
      ads(0),
      size(0),
      inode(0),
      seq(0),
      uid(0),
      gid(0),
      owner_id(0),
      secure_id(0) {
  memset(object_id, 0, sizeof(object_id));
}

std::string FileInfo::getStringRep() const {
  // for ease of debugging
  std::stringstream output;

  output << "name: \"" << this->name << "\"\n"
         << "path: \"" << this->path << "\"\n"
         << "parent: " << this->filename.parent.inode << ","
         << this->filename.parent.sequence << "\n"
         << "btime:    " << this->standard_info_times.btime << "\n"
         << "mtime:    " << this->standard_info_times.mtime << "\n"
         << "ctime:    " << this->standard_info_times.ctime << "\n"
         << "atime:    " << this->standard_info_times.atime << "\n"
         << "fn_btime: " << this->filename.file_name_times.btime << "\n"
         << "fn_mtime: " << this->filename.file_name_times.mtime << "\n"
         << "fn_ctime: " << this->filename.file_name_times.ctime << "\n"
         << "fn_atime: " << this->filename.file_name_times.atime << "\n"
         << "type: " << typeNameFromInt(this->type) << "\n"
         << "active: " << (this->active > 0 ? "true" : "false") << "\n";

  std::stringstream vflags, fn_flags;
  vflags << "0x" << std::hex << std::setfill('0') << std::setw(8)
         << this->flag_val;
  fn_flags << "0x" << std::hex << std::setfill('0') << std::setw(8)
           << this->filename.flags;

  output << "flags: " << vflags.str() << "\nfn_flags: " << fn_flags.str()
         << "\n"
         << "ads: " << (this->ads == 0 ? "false" : "true") << "\n"
         << "allocated: " << this->filename.allocated_size << "\n"
         << "size:      " << this->filename.real_size << "\n"
         << "inode: " << this->inode << "\n"
         << "seq: " << this->seq << "\n"
         << "uid: " << this->uid << "\n"
         << "gid: " << this->gid << "\n"
         << "owner_id: " << this->owner_id << "\n"
         << "sid: " << this->sid << "\n";

  std::stringstream oid;
  for (int i = 0; i < 16; ++i) {
    oid << std::hex << std::setfill('0') << std::setw(2)
        << static_cast<unsigned>(this->object_id[i]);
  }

  output << "object_id: " << oid.str() << "\n";
  return output.str();
}

std::string typeNameFromInt(int t) {
  switch (t) {
  case TSK_FS_META_TYPE_UNDEF:
    return std::string("Undefined");
  case TSK_FS_META_TYPE_REG:
    return std::string("File");
  case TSK_FS_META_TYPE_DIR:
    return std::string("Directory");
  default:
    return std::string("Unknown");
  }
}
}