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

#include <CoreServices/CoreServices.h>
#include <IOKit/IOKitLib.h>

#include <string>

struct SystemInformation final {
  std::string board_id;
  std::string smc_ver;
  std::string sys_uuid;
  std::string build_num;
  std::string rom_ver;
  std::string hw_ver;
  std::string os_ver;
  std::string mac_addr;
};

void getEFIVersion(std::string& version);
void getSMCVersion(std::string& version);
void getOSVersion(std::string& version, std::string& build);
void getMACAddress(std::string& mac);

void getHardwareModel(std::string& model, io_registry_entry_t registry);
void getBoardID(std::string& board_id, io_registry_entry_t registry);

void getHostUUID(std::string& uuid, io_registry_entry_t registry);

void getSystemInformation(SystemInformation& system_info);
