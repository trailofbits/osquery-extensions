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

#pragma once

namespace trailofbits {
template <typename Detail>
class IStatus final {
  bool success_;
  Detail detail_;

 public:
  IStatus(bool success = false, Detail error_detail = Detail::Undetermined)
      : success_(success), detail_(error_detail) {}

  bool success() const {
    return success_;
  }

  Detail detail() const {
    return detail_;
  }
};
} // namespace trailofbits
