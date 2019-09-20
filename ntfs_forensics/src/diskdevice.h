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

#include <memory>
#include <string>

#include <boost/noncopyable.hpp>

#include <tsk/libtsk.h>

#include <osquery/sdk/sdk.h>

namespace trailofbits {
class DiskDevice;
using DiskDeviceRef = std::shared_ptr<DiskDevice>;

/// This class is a wrapper around the TSK image information type
class DiskDevice final : private boost::noncopyable {
  TSK_IMG_INFO* img_info{nullptr};

  /// Constructs a new object by opening the specified device. Will throw an
  /// osquery::Status object in case of error
  DiskDevice(const std::string& device_name);

 public:
  /// Constructs a new object by opening the specified device. This function
  /// never throws an exception
  static osquery::Status create(DiskDeviceRef& disk_device,
                                const std::string& device_name) noexcept;

  /// Destructor
  ~DiskDevice();

  /// Returns the wrapped TSK object
  TSK_IMG_INFO* imageInfo();
};
}
