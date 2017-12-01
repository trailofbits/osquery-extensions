/*
 *  Copyright (c) 2017-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "extension.h"
#include "efigy.h"

osquery::TableColumns EFIgyTablePlugin::columns() const {
  return {
      std::make_tuple("latest_efi_version",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),
      std::make_tuple(
          "efi_version", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
      std::make_tuple("efi_version_status",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),

      std::make_tuple("latest_os_version",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT),
      std::make_tuple(
          "os_version", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
      std::make_tuple("build_number_status",
                      osquery::TEXT_TYPE,
                      osquery::ColumnOptions::DEFAULT)};
}

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
