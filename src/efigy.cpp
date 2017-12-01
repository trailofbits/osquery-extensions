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

#include <iostream>
#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/optional/optional.hpp>

#include "efigy.h"

namespace pt = boost::property_tree;

namespace {
osquery::Status getPostRequestData(std::string& json,
                                   const SystemInformation& system_info) {
  json.clear();

  if (system_info.smc_ver.empty() || system_info.build_num.empty() ||
      system_info.hw_ver.empty() || system_info.os_ver.empty() ||
      system_info.sys_uuid.empty() || system_info.mac_addr.empty()) {
    return osquery::Status(1, "Incomplete SystemInformation object received");
  }

  pt::ptree system_info_object;
  system_info_object.put("board_id", system_info.board_id);
  system_info_object.put("smc_ver", system_info.smc_ver);

  {
    // std::string buffer = system_info.mac_addr + system_info.sys_uuid;

    // osquery::Hash hasher(osquery::HASH_TYPE_SHA256);
    // hasher.update(buffer.data(), buffer.size());

    // system_info_object.put("hashed_uuid", hasher.digest());
    system_info_object.put(
        "hashed_uuid",
        "96ca672ac966502030b692ed3708e8671b5a0ff84dedea6ad1882ee75e6b4be3");
  }

  system_info_object.put("build_num", system_info.build_num);
  system_info_object.put("rom_ver", system_info.rom_ver);
  system_info_object.put("hw_ver", system_info.hw_ver);
  system_info_object.put("os_ver", system_info.os_ver);

  std::stringstream json_stream;
  pt::json_parser::write_json(json_stream, system_info_object);
  json = json_stream.str();

  return osquery::Status(0, "OK");
}
} // namespace

osquery::Status queryEFIgy(ServerResponse& response,
                           const SystemInformation& system_info) {
  response = {};

  std::string request_data;
  auto status = getPostRequestData(request_data, system_info);
  if (!status.ok()) {
    return status;
  }

  /*osquery::http::Client::Options client_options;
  client_options.always_verify_peer(true)
      .openssl_options(SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
                       SSL_OP_NO_TLSv1_1)

      .openssl_certificate("/etc/ssl/cert.pem")
      .openssl_sni_hostname("api.efigy.io");

  client_options.timeout(5).follow_redirects(true);*/

  std::string raw_server_response;

  try {
    /*osquery::http::Request
    server_request("https://api.efigy.io/apple/oneshot");

    server_request << osquery::http::Request::Header("User-Agent", "osquery");
    server_request << osquery::http::Request::Header("Content-type",
                                                     "application/json");

    server_request << osquery::http::Request::Header("Accept",
                                                     "application/json");

    osquery::http::Client client(client_options);
    auto server_response = client.post(server_request, request_data);
    raw_server_response = server_response.body();*/
    raw_server_response = "{}";

  } catch (const pt::json_parser_error& e) {
    return osquery::Status(
        1, std::string("Invalid JSON in server response: ") + e.what());

  } catch (const std::exception& e) {
    return osquery::Status(
        1, std::string("Could not query the EFIgy API endpoint: ") + e.what());
  }

  std::stringstream json_stream(raw_server_response);

  pt::ptree json_response;
  pt::read_json(json_stream, json_response);

  auto latest_efi_version =
      json_response.get_optional<std::string>("latest_efi_version.msg");

  if (!latest_efi_version || latest_efi_version->empty()) {
    return osquery::Status(
        1, std::string("Invalid server response: ") + raw_server_response);
  }

  if (json_response.get_optional<std::string>("latest_efi_version.error")) {
    return osquery::Status(
        1,
        std::string("The server has returned the following error: ") +
            latest_efi_version.get());
  }

  auto latest_os_version =
      json_response.get_optional<std::string>("latest_os_version.msg");

  if (!latest_os_version || latest_os_version->empty()) {
    return osquery::Status(
        1, std::string("Invalid server response: ") + raw_server_response);
  }

  if (json_response.get_optional<std::string>("latest_os_version.error")) {
    return osquery::Status(
        1,
        std::string("The server has returned the following error: ") +
            latest_os_version.get());
  }

  auto latest_build_number =
      json_response.get_optional<std::string>("latest_build_number.msg");

  if (!latest_build_number || latest_build_number->empty()) {
    return osquery::Status(
        1, std::string("Invalid server response: ") + raw_server_response);
  }

  if (json_response.get_optional<std::string>("latest_build_number.error")) {
    return osquery::Status(
        1,
        std::string("The server has returned the following error: ") +
            latest_build_number.get());
  }

  response.latest_efi_version = latest_efi_version.get();
  response.latest_os_version = latest_os_version.get();
  response.latest_build_number = latest_build_number.get();

  return osquery::Status(0, "OK");
}
