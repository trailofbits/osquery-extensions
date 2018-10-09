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
