/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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
