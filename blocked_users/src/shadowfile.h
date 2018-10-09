#pragma once

#include <cstdio>
#include <memory>
#include <shadow.h>
#include <vector>

#include "shadowentry.h"

class ShadowFile final {
 public:
  ShadowFile();
  ~ShadowFile();

  using const_iterator = std::vector<ShadowEntry>::const_iterator;

  const_iterator begin() const noexcept;
  const_iterator end() const noexcept;

  const_iterator cbegin() const noexcept;
  const_iterator cend() const noexcept;

 private:
  FILE* shadow_stream;
  int64_t strings_bufsize;
  std::vector<ShadowEntry> shadow_entries;
};
