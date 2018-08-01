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

#include <Windows.h>

#include "ntfsfilenameattributecontents.h"

namespace trailofbits {

bool NTFSFileNameAttributeContents::valid() const {
  constexpr uint64_t one_year = 315569520000000ULL; //one year in hunded-nanoseconds

  // the filetime for 1990 is calculated by adding the magic value for
  // the number of hundred-nanoseconds between 1601 and 1970
  // to 20 times the number of hundred-nanoseconds in a year
  constexpr uint64_t _1990 = 116444736000000000ULL + (20ULL * one_year);

  // MicroSoft strongly suggests converting a FILETIME to a ULARGE_INTEGER
  // and manipulating its QuadPart
  FILETIME current_time;
  ::GetSystemTimeAsFileTime(&current_time);
  ULARGE_INTEGER one_year_ahead;
  one_year_ahead.LowPart = current_time.dwLowDateTime;
  one_year_ahead.HighPart = current_time.dwHighDateTime;
  one_year_ahead.QuadPart += one_year;

  return (one_year_ahead.QuadPart > file_name_times.atime) &&
         (file_name_times.atime > _1990) &&
         (one_year_ahead.QuadPart > file_name_times.btime) &&
         (file_name_times.btime > _1990) &&
         (one_year_ahead.QuadPart > file_name_times.ctime) &&
         (file_name_times.ctime > _1990) &&
         (one_year_ahead.QuadPart > file_name_times.mtime) &&
         (file_name_times.mtime > _1990);
}
}
