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
