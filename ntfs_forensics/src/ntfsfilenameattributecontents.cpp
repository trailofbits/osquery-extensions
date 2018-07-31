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

bool ntfs_filename_attribute_contents_t::valid() const {
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