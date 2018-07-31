#pragma once

#include "ntfs_types.h"
#include <string>

namespace trailofbits {
struct ntfs_filename_attribute_contents_t final {
  ntfs_mft_file_reference_t parent;
  timestamp_t file_name_times;
  std::string filename;

  uint64_t allocated_size{0U};
  uint64_t real_size{0U};
  uint32_t flags{0U};
  uint8_t name_length{0U};

  bool valid() const;
};
}