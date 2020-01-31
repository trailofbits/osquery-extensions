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

#include "efigy.h"

#include <iostream>
#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/optional/optional.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

namespace trailofbits {
namespace pt = boost::property_tree;

namespace {
void getPostRequestData(std::string& json,
                        const SystemInformation& system_info) {
  json.clear();

  if (system_info.smc_ver.empty() || system_info.build_num.empty() ||
      system_info.hw_ver.empty() || system_info.os_ver.empty() ||
      system_info.sys_uuid.empty() || system_info.mac_addr.empty()) {
    throw std::runtime_error("Incomplete SystemInformation object received");
  }

  pt::ptree system_info_object;
  system_info_object.put("board_id", system_info.board_id);
  system_info_object.put("smc_ver", system_info.smc_ver);

  {
    std::string buffer = system_info.mac_addr + system_info.sys_uuid;
    std::string digest = getSha256Hash(
        reinterpret_cast<const std::uint8_t*>(buffer.data()), buffer.size());

    system_info_object.put("hashed_uuid", digest);
  }

  system_info_object.put("build_num", system_info.build_num);
  system_info_object.put("rom_ver", system_info.rom_ver);
  system_info_object.put("hw_ver", system_info.hw_ver);
  system_info_object.put("os_ver", system_info.os_ver);

  std::stringstream json_stream;
  pt::json_parser::write_json(json_stream, system_info_object);
  json = json_stream.str();
}
} // namespace

void queryEFIgy(ServerResponse& response,
                const SystemInformation& system_info) {
  response = {};

  std::string raw_server_response;
  pt::ptree json_response;

  try {
    std::string request_data;
    getPostRequestData(request_data, system_info);

    raw_server_response =
        httpPostRequest("https://api.efigy.io/apple/oneshot", request_data);

    std::stringstream json_stream(raw_server_response);
    pt::read_json(json_stream, json_response);

  } catch (const pt::json_parser_error& e) {
    throw std::runtime_error(std::string("Invalid JSON in server response: ") +
                             e.what());

  } catch (const std::exception& e) {
    throw std::runtime_error(
        std::string("Could not query the EFIgy API endpoint: ") + e.what());
  }

  auto latest_efi_version =
      json_response.get_optional<std::string>("latest_efi_version.msg");

  if (!latest_efi_version || latest_efi_version->empty()) {
    throw std::runtime_error(std::string("Invalid server response: ") +
                             raw_server_response);
  }

  if (json_response.get_optional<std::string>("latest_efi_version.error")) {
    throw std::runtime_error(
        std::string("The server has returned the following error: ") +
        latest_efi_version.get());
  }

  auto latest_os_version =
      json_response.get_optional<std::string>("latest_os_version.msg");

  if (!latest_os_version || latest_os_version->empty()) {
    throw std::runtime_error(std::string("Invalid server response: ") +
                             raw_server_response);
  }

  if (json_response.get_optional<std::string>("latest_os_version.error")) {
    throw std::runtime_error(
        std::string("The server has returned the following error: ") +
        latest_os_version.get());
  }

  auto latest_build_number =
      json_response.get_optional<std::string>("latest_build_number.msg");

  if (!latest_build_number || latest_build_number->empty()) {
    throw std::runtime_error(std::string("Invalid server response: ") +
                             raw_server_response);
  }

  if (json_response.get_optional<std::string>("latest_build_number.error")) {
    throw std::runtime_error(
        std::string("The server has returned the following error: ") +
        latest_build_number.get());
  }

  response.latest_efi_version = latest_efi_version.get();
  response.latest_os_version = latest_os_version.get();
  response.latest_build_number = latest_build_number.get();
}
} // namespace trailofbits
