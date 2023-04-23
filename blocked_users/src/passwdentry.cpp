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

#include "passwdentry.h"

#include <memory>
#include <pwd.h>

#include <osquery/sdk.h>

PasswdEntry::PasswdEntry(uid_t uid) : passwd_entry{} {
  int64_t strings_bufsize;
  strings_buffer = allocatePasswdBuffer(strings_bufsize);

  struct passwd* result;
  int error = getpwuid_r(uid,
                         &passwd_entry,
                         strings_buffer.get(),
                         static_cast<uint64_t>(strings_bufsize),
                         &result);

  if (error == 0) {
    if (result == nullptr) {
      throw osquery::Status(1, "No user found with uid " + std::to_string(uid));
    }
  } else {
    throw osquery::Status(1,
                          "Failed to retrieve the user with uid " +
                              std::to_string(uid) + " due to error " +
                              std::to_string(error));
  }
}

PasswdEntry::PasswdEntry(const std::string& username) : passwd_entry{} {
  int64_t strings_bufsize;
  strings_buffer = allocatePasswdBuffer(strings_bufsize);

  struct passwd* result;
  int error = getpwnam_r(username.c_str(),
                         &passwd_entry,
                         strings_buffer.get(),
                         static_cast<uint64_t>(strings_bufsize),
                         &result);

  if (error == 0) {
    if (result == nullptr) {
      throw osquery::Status(1, "No user found with userename " + username);
    }
  } else {
    throw osquery::Status(1,
                          "Failed to retrieve the user with uid " + username +
                              " due to error " + std::to_string(error));
  }
}

const char* PasswdEntry::username() const noexcept {
  return passwd_entry.pw_name;
}

uid_t PasswdEntry::uid() const noexcept {
  return passwd_entry.pw_uid;
}

bool PasswdEntry::isEmpty() const noexcept {
  return passwd_entry.pw_name == nullptr;
}

std::unique_ptr<char[]> PasswdEntry::allocatePasswdBuffer(
    int64_t& strings_bufsize) {
  strings_bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);

  if (strings_bufsize == -1) {
    strings_bufsize = 2048;
  }

  return std::unique_ptr<char[]>(
      new char[static_cast<uint64_t>(strings_bufsize)]);
}
