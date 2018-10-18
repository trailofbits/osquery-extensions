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

#include "shadowentry.h"

#include <ctime>

ShadowEntry::ShadowEntry(ShadowEntry&& other) noexcept
    : shadow(std::move(other.shadow)),
      strings_buffer(std::move(other.strings_buffer)),
      account_is_expired(other.account_is_expired) {}

ShadowEntry::ShadowEntry(const spwd& shadow_,
                         std::unique_ptr<char[]>&& strings_buffer_)
    : shadow(shadow_), strings_buffer(std::move(strings_buffer_)) {
  if (shadow.sp_expire != -1) {
    int current_days = static_cast<int>(time(nullptr) / (60 * 60 * 24));
    account_is_expired = current_days >= shadow.sp_expire;
  }
}

ShadowEntry::ShadowEntry(size_t strings_bufsize)
    : shadow{},
      strings_buffer(std::unique_ptr<char[]>(new char[strings_bufsize])),
      account_is_expired(false) {}

ShadowEntry& ShadowEntry::operator=(ShadowEntry&& other) noexcept {
  std::swap(shadow, other.shadow);
  std::swap(strings_buffer, other.strings_buffer);
  account_is_expired = other.account_is_expired;

  return *this;
}

char* ShadowEntry::username() const noexcept {
  return shadow.sp_namp;
}

char* ShadowEntry::password() const noexcept {
  return shadow.sp_pwdp;
}

int64_t ShadowEntry::expire_date() const noexcept {
  return shadow.sp_expire;
}

bool ShadowEntry::isPasswordLocked() const noexcept {
  return shadow.sp_pwdp[0] == '!';
}

bool ShadowEntry::accountIsExpired() const noexcept {
  return account_is_expired;
}
