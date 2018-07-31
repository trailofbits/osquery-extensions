#pragma once

#include "ntfs_types.h"
#include <string>

namespace trailofbits {
typedef struct ntfs_filename_attribute_contents {
  ntfs_mft_file_reference_t parent;
  timestamp_t file_name_times;
  uint64_t allocated_size;
  uint64_t real_size;
  uint32_t flags;
  uint8_t name_length;
  std::string filename;

  bool valid() const;
  ntfs_filename_attribute_contents();
} ntfs_filename_attribute_contents_t;
}