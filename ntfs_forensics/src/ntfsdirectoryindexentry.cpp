#include <iomanip>
#include <sstream>

#include "ntfsdirectoryindexentry.h"

namespace trailofbits {
ntfs_directory_index_entry::ntfs_directory_index_entry()
    : entry_length(0), name_length(0), flags(0), child_vcn(0), slack_addr(0) {}

std::string ntfs_directory_index_entry::getStringRep() const {
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

bool ntfs_directory_index_entry::valid() const {
  return filename.valid() && entry_length >= 0x52 && entry_length < 4096 &&
         flags < 4 && child_vcn < 4096 && name_length < 4096;
}
}