#include "shadowfile.h"

#include <cstdio>
#include <exception>
#include <iostream>
#include <memory>
#include <pwd.h>
#include <string>
#include <unistd.h>

#include <osquery/sdk.h>

ShadowFile::ShadowFile() {
  shadow_stream = fopen("/etc/shadow", "r");

  strings_bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);

  if (strings_bufsize == -1) {
    strings_bufsize = 1024;
  }

  struct spwd* result;

  int error = 0;
  do {
    ShadowEntry shadow_entry(static_cast<size_t>(strings_bufsize));
    error = fgetspent_r(shadow_stream,
                        &shadow_entry.shadow,
                        shadow_entry.strings_buffer.get(),
                        static_cast<size_t>(strings_bufsize),
                        &result);

    if (result != nullptr) {
      if (shadow_entry.shadow.sp_expire != -1) {
        int current_days = static_cast<int>(time(nullptr) / (60 * 60 * 24));
        shadow_entry.account_is_expired =
            current_days >= shadow_entry.shadow.sp_expire;
      }
      shadow_entries.push_back(std::move(shadow_entry));
    }

  } while (result != nullptr);

  if (error && error != ENOENT) {
    throw osquery::Status(
        1, "Failed to retrieve shadow entry, error " + std::to_string(error));
  }
}

ShadowFile::const_iterator ShadowFile::begin() const noexcept {
  return shadow_entries.begin();
}

ShadowFile::const_iterator ShadowFile::end() const noexcept {
  return shadow_entries.end();
}

ShadowFile::const_iterator ShadowFile::cbegin() const noexcept {
  return shadow_entries.cbegin();
}

ShadowFile::const_iterator ShadowFile::cend() const noexcept {
  return shadow_entries.cend();
}

ShadowFile::~ShadowFile() {
  fclose(shadow_stream);
}
