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

#include "device.h"

namespace trailofbits {
Device::Device(const std::string& device) {
  if (device.empty()) {
    throw std::runtime_error("Invalid device specified");
  }

  const char* paths[1] = {device.c_str()};
  img_info = tsk_img_open_utf8(1, paths, TSK_IMG_TYPE_DETECT, 0);
  if (img_info == nullptr) {
    throw std::runtime_error("Unable to open device");
  }
}

Device::~Device() {
  tsk_img_close(img_info);
}

TSK_IMG_INFO* Device::imageInfo() {
  return img_info;
}
}
