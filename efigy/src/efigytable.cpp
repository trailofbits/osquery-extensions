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

#include "Version.h"
#include "efigytable.h"
#include "efigy.h"
#include "Extension.h"
#include "utils.h"

#if OSQUERY_VERSION_NUMBER >= OSQUERY_SDK_VERSION(4, 0)
#include <osquery/sql/dynamic_table_row.h>
#endif

#include <curl/curl.h>

namespace trailofbits {
osquery::TableColumns EFIgyTablePlugin::columns() const {
  // clang-format off
  return {
      std::make_tuple("latest_efi_version",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("efi_version",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("efi_version_status",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("latest_os_version",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("os_version",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("build_number_status",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT)
  };
  // clang-format on
}

#if OSQUERY_VERSION_NUMBER < OSQUERY_SDK_VERSION(4, 0)
osquery::QueryData EFIgyTablePlugin::generate(osquery::QueryContext& request) {
  SystemInformation system_info;
  ServerResponse response;

  try {
    getSystemInformation(system_info);
    queryEFIgy(response, system_info);

  } catch (const std::exception& e) {
    VLOG(1) << e.what();

    osquery::Row r;
    r["efi_version_status"] = r["os_version_status"] =
        r["build_number_status"] = "error";

    return {r};
  }

  osquery::Row r;
  r["latest_efi_version"] = response.latest_efi_version;
  r["efi_version"] = system_info.rom_ver;
  if (system_info.rom_ver == response.latest_efi_version) {
    r["efi_version_status"] = "success";
  } else {
    r["efi_version_status"] = "failure";
  }

  r["latest_os_version"] = response.latest_os_version;
  r["os_version"] = system_info.os_ver;
  if (system_info.os_ver == response.latest_os_version) {
    r["os_version_status"] = "success";
  } else {
    r["os_version_status"] = "failure";
  }

  r["latest_build_number"] = response.latest_build_number;
  r["build_number"] = system_info.build_num;
  if (system_info.build_num == response.latest_build_number) {
    r["build_number_status"] = "success";
  } else {
    r["build_number_status"] = "failure";
  }

  return {r};
}
#else
osquery::TableRows EFIgyTablePlugin::generate(osquery::QueryContext& request) {
  SystemInformation system_info;
  ServerResponse response;
  osquery::TableRows result;

  try {
    getSystemInformation(system_info);
    queryEFIgy(response, system_info);

  } catch (const std::exception& e) {
    VLOG(1) << e.what();

    osquery::Row r;
    r["efi_version_status"] = r["os_version_status"] =
        r["build_number_status"] = "error";

    result.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(r))));
    return result;
  }

  osquery::Row r;
  r["latest_efi_version"] = response.latest_efi_version;
  r["efi_version"] = system_info.rom_ver;
  if (system_info.rom_ver == response.latest_efi_version) {
    r["efi_version_status"] = "success";
  } else {
    r["efi_version_status"] = "failure";
  }

  r["latest_os_version"] = response.latest_os_version;
  r["os_version"] = system_info.os_ver;
  if (system_info.os_ver == response.latest_os_version) {
    r["os_version_status"] = "success";
  } else {
    r["os_version_status"] = "failure";
  }

  r["latest_build_number"] = response.latest_build_number;
  r["build_number"] = system_info.build_num;
  if (system_info.build_num == response.latest_build_number) {
    r["build_number_status"] = "success";
  } else {
    r["build_number_status"] = "failure";
  }

  result.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(r))));
  return result;
}
#endif

EFIgyTablePlugin::EFIgyTablePlugin() {
  curl_global_init(CURL_GLOBAL_ALL);
}

EFIgyTablePlugin::~EFIgyTablePlugin() {
  curl_global_cleanup();
}
} // namespace trailofbits
