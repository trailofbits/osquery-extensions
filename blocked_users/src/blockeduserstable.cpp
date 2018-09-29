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

#include "blockeduserstable.h"

#include <iostream>
#include <pwd.h>
#include <shadow.h>
#include <sys/types.h>

#include <trailofbits/extutils.h>

namespace trailofbits {
namespace {
const std::string kUserModCommand = "/usr/sbin/usermod";

std::vector<std::string> lockArgs{"--lock", "--expiredate", "1", ""};
std::vector<std::string> unlockArgs{"--unlock", "--expiredate", "", ""};

struct LockedUser final {
  uid_t uid;
  std::string username;
};

using LockedUsers = std::vector<LockedUser>;

osquery::Status uidToUsername(std::string& username, uid_t uid) {
  struct passwd* user_passwd = getpwuid(uid);

  if (user_passwd != nullptr) {
    username = user_passwd->pw_name;
  } else {
    return osquery::Status(1, "No user found with uid: " + std::to_string(uid));
  }

  return osquery::Status(0);
}

osquery::Status usernameToUid(uid_t& uid, const std::string& username) {
  struct passwd* user_passwd = getpwnam(username.c_str());

  if (user_passwd != nullptr) {
    uid = user_passwd->pw_uid;
  } else {
    return osquery::Status(1, "No user found with username: " + username);
  }

  return osquery::Status(0);
}

osquery::Status parseUid(uid_t& uid, const std::string& str_uid) {
  auto user_id = std::strtoul(str_uid.c_str(), nullptr, 10);

  if (errno == ERANGE || user_id > UINT_MAX) {
    errno = 0;
    return osquery::Status(1, "Invalid uid given: " + str_uid);
  }

  uid = static_cast<uid_t>(user_id);

  return osquery::Status(0);
}

osquery::Status validateUserName(const std::string& name) {
  // Dummy check, to be improved?
  if (name.find("'") != std::string::npos) {
    return osquery::Status::failure("Unsafe character found in the username");
  }

  return osquery::Status(0);
}

osquery::Status lockUser(const std::string& username) {
  auto status = validateUserName(username);
  if (!status.ok()) {
    return status;
  }

  lockArgs.back() = username;

  ProcessOutput output;
  if (!ExecuteProcess(output, kUserModCommand, lockArgs)) {
    std::string command = kUserModCommand;

    for (auto arg : lockArgs) {
      command += " " + arg;
    }
    // TODO: this is for debug -> osquery::Status(1, "Failed to run lock
    // command: " + command);

    return osquery::Status(1, "Failed to execute the usermod process");
  }

  if (output.exit_code != 0) {
    return osquery::Status(1,
                           "Exit code: " + std::to_string(output.exit_code) +
                               " Output: " + output.std_output +
                               " Error: " + output.std_error);
  }

  return osquery::Status(0);
}

osquery::Status unlockUser(const std::string& username) {
  auto status = validateUserName(username);
  if (!status.ok()) {
    return status;
  }

  unlockArgs.back() = username;

  ProcessOutput output;
  if (!ExecuteProcess(output, kUserModCommand, unlockArgs)) {
    std::string command = kUserModCommand;

    for (auto arg : unlockArgs) {
      command += " " + arg;
    }
    // TODO: this is for debug -> osquery::Status(1, "Failed to run lock
    // command: " + command);

    return osquery::Status(1, "Failed to execute the usermod process");
  }

  if (output.exit_code != 0) {
    return osquery::Status(1,
                           "Exit code: " + std::to_string(output.exit_code) +
                               " Output: " + output.std_output +
                               " Error: " + output.std_error);
  }

  return osquery::Status(0);
}

osquery::Status getLockedUserList(LockedUsers& locked_users) {
  locked_users.clear();

  setspent();

  bool more_shadow_entries = true;

  while (more_shadow_entries) {
    struct spwd* shadow_entry = getspent();

    if (shadow_entry != nullptr) {
      struct passwd* passwd_entry = getpwnam(shadow_entry->sp_namp);

      if (passwd_entry != nullptr && shadow_entry->sp_pwdp[0] == '!') {
        locked_users.push_back({passwd_entry->pw_uid, shadow_entry->sp_namp});
      }
    } else {
      more_shadow_entries = false;
    }
  }

  endspent();

  return osquery::Status(0);
}

osquery::Status GetRowData(osquery::Row& row,
                           const std::string& json_value_array) {
  row.clear();

  rapidjson::Document document;
  document.Parse(json_value_array);
  if (document.HasParseError() || !document.IsArray()) {
    return osquery::Status(1, "Invalid json received by osquery");
  }

  if (document.Size() != 2U) {
    return osquery::Status(1,
                           "Wrong column count " +
                               std::to_string(document.Size()) +
                               " received, 2 expected");
  }

  if (!document[0].IsNull()) {
    row["uid"] = document[0].GetString();
  }

  if (!document[1].IsNull()) {
    row["username"] = document[1].GetString();
  }

  return osquery::Status(0);
}
} // namespace

osquery::TableColumns BlockedUsersTable::columns() const {
  // clang-format off
  return {
    std::make_tuple("uid", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("username", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT)
  };
  // clang-format on
}

osquery::QueryData BlockedUsersTable::generate(osquery::QueryContext& request) {
  LockedUsers locked_user_list;
  auto status = getLockedUserList(locked_user_list);
  if (!status.ok()) {
    std::stringstream error;
    error << "Failed to generate the list of locked users: "
          << status.getMessage();

    return {{std::make_pair("status", "failure"),
             std::make_pair("message", error.str())}};
  }

  osquery::QueryData results;
  for (const auto& locked_user : locked_user_list) {
    osquery::Row r = {};
    r["uid"] = std::to_string(locked_user.uid);
    r["rowid"] = r["uid"];
    r["username"] = locked_user.username;
    results.push_back(std::move(r));
  }

  return results;
}

osquery::QueryData BlockedUsersTable::insert(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  osquery::Row row;
  auto status = GetRowData(row, request.at("json_value_array"));
  if (!status.ok()) {
    std::stringstream error;
    error << "Failed to handle the insert: " << status.getMessage();

    return {{std::make_pair("status", "failure"),
             std::make_pair("message", error.str())}};
  }

  if (row.count("uid") == row.count("username")) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message",
                            "Either the username or the uid is required")}};
  }

  std::string username;
  uid_t user_id;

  auto username_it = row.find("username");
  if (username_it != row.end()) {
    username = username_it->second;
    status = usernameToUid(user_id, username);

  } else {
    const auto& str_user_id = row.at("uid");
    status = parseUid(user_id, str_user_id);

    if (status.ok()) {
      status = uidToUsername(username, user_id);
    }
  }

  if (!status.ok()) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", status.getMessage())}};
  }

  status = lockUser(username);
  if (!status.ok()) {
    return {
        {std::make_pair("status", "failure"),
         std::make_pair("message",
                        "Failed to lock the user: " + status.getMessage())}};
  }

  osquery::Row result;
  result["id"] = std::to_string(user_id);
  result["status"] = "success";
  return {result};
}

osquery::QueryData BlockedUsersTable::delete_(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  std::string str_user_id = request.at("id");
  uid_t user_id;
  auto status = parseUid(user_id, str_user_id);

  if (!status.ok()) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", status.getMessage())}};
  }

  std::string username;
  status = uidToUsername(username, user_id);

  if (!status.ok()) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", status.getMessage())}};
  }

  status = unlockUser(username);
  if (!status.ok()) {
    return {
        {std::make_pair("status", "failure"),
         std::make_pair("message",
                        "Failed to unlock the user: " + status.getMessage())}};
  }

  return {{std::make_pair("status", "success")}};
}

osquery::QueryData BlockedUsersTable::update(osquery::QueryContext&,
                                             const osquery::PluginRequest&) {
  return {{std::make_pair("status", "failure"),
           std::make_pair("message", "Unsupported operation")}};
}
} // namespace trailofbits
