#pragma once

#include <memory>
#include <shadow.h>
#include <string>

class ShadowFile;

class ShadowEntry final {
 public:
  ShadowEntry() = delete;

  ShadowEntry(ShadowEntry&& other) noexcept;

  ShadowEntry(const struct spwd& shadow_,
              std::unique_ptr<char[]>&& strings_buffer_);

  ShadowEntry(size_t strings_bufsize);

  ShadowEntry& operator=(ShadowEntry&& other) noexcept;

  char* username() const noexcept;
  char* password() const noexcept;
  int64_t expire_date() const noexcept;
  bool isPasswordLocked() const noexcept;
  bool accountIsExpired() const noexcept;

 private:
  struct spwd shadow;
  std::unique_ptr<char[]> strings_buffer;
  bool account_is_expired;

  friend ShadowFile;
};
