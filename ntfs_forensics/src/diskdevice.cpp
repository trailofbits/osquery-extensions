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

#include "diskdevice.h"

namespace trailofbits {
DiskDevice::DiskDevice(const std::string& device_name) {
  if (device_name.empty()) {
    throw osquery::Status(1, "Invalid device specified");
  }

  const char* paths[1] = {device_name.c_str()};
  img_info = tsk_img_open_utf8(1, paths, TSK_IMG_TYPE_DETECT, 0);
  if (img_info == nullptr) {
    throw osquery::Status(1, "Unable to open the device");
  }
}

osquery::Status DiskDevice::create(DiskDeviceRef& disk_device,
                                   const std::string& device_name) {
  try {
    auto ptr = new DiskDevice(device_name);
    disk_device.reset(ptr);

    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

DiskDevice::~DiskDevice() {
  tsk_img_close(img_info);
}

TSK_IMG_INFO* DiskDevice::imageInfo() {
  return img_info;
}
}
