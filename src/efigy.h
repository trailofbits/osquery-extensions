/*
 *  Copyright (c) 2017-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>

#include <osquery/sdk.h>

#include "utils.h"

struct ServerResponse final {
  std::string latest_efi_version;
  std::string latest_os_version;
  std::string latest_build_number;
};

osquery::Status queryEFIgy(ServerResponse& response,
                           const SystemInformation& system_info);
