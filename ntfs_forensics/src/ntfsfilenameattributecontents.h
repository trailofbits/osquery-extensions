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
}