#pragma once

#include <memory>
#include <pwd.h>
#include <string>

class PasswdEntry final {
 public:
  PasswdEntry(uid_t uid);
  PasswdEntry(const std::string& username);
  ~PasswdEntry() = default;

  const char* username() const noexcept;
  uid_t uid() const noexcept;

  bool isEmpty() const noexcept;

 private:
  std::unique_ptr<char[]> allocatePasswdBuffer(int64_t& strings_bufsize);
  std::unique_ptr<char[]> strings_buffer;
  struct passwd passwd_entry;
};
