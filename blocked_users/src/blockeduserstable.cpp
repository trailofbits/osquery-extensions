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

#include <dlfcn.h>
#include <proc/readproc.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <sys/types.h>

#include <algorithm>
#include <cctype>
#include <iostream>

#include <boost/algorithm/string.hpp>
#include <boost/thread.hpp>

#include <trailofbits/extutils.h>

#include "passwdentry.h"
#include "shadowfile.h"

namespace trailofbits {
namespace {
const std::string kUserModCommand = "/usr/sbin/usermod";

std::vector<std::string> lockArgs{"--lock", "--expiredate", "1", ""};
std::vector<std::string> unlockArgs{"--unlock", "--expiredate", "", ""};

boost::shared_mutex passwd_mutex;

struct LockedUser final {
  uid_t uid;
  std::string username;
};

using LockedUsers = std::vector<LockedUser>;

typedef struct {
  const char* name;
  const char* message;
  int _need_free;
} sd_bus_error;

using sd_bus = void;
using sd_bus_message = void;
using sd_bus_default_system_ptr = int (*)(sd_bus** ret);
using sd_bus_call_method_ptr = int (*)(sd_bus* bus,
                                       const char* destination,
                                       const char* path,
                                       const char* interface,
                                       const char* member,
                                       sd_bus_error* ret_error,
                                       sd_bus_message** reply,
                                       const char* types,
                                       ...);
using sd_bus_flush_ptr = int (*)(sd_bus* bus);
using sd_bus_close_ptr = int (*)(sd_bus* bus);
using sd_bus_unref_ptr = int (*)(sd_bus* bus);

sd_bus_default_system_ptr sd_bus_default_system = nullptr;
sd_bus_call_method_ptr sd_bus_call_method = nullptr;
sd_bus_flush_ptr sd_bus_flush = nullptr;
sd_bus_close_ptr sd_bus_close = nullptr;
sd_bus_unref_ptr sd_bus_unref = nullptr;
sd_bus* sd_bus_ptr = nullptr;

bool loadSystemd() {
  void* systemd_library = dlopen("libsystemd.so.0", RTLD_LAZY | RTLD_GLOBAL);

  bool init_success = true;

  if (systemd_library != nullptr) {
    sd_bus_default_system = reinterpret_cast<sd_bus_default_system_ptr>(
        dlsym(systemd_library, "sd_bus_default_system"));
    sd_bus_call_method = reinterpret_cast<sd_bus_call_method_ptr>(
        dlsym(systemd_library, "sd_bus_call_method"));
    sd_bus_flush = reinterpret_cast<sd_bus_flush_ptr>(
        dlsym(systemd_library, "sd_bus_flush"));
    sd_bus_close = reinterpret_cast<sd_bus_close_ptr>(
        dlsym(systemd_library, "sd_bus_close"));
    sd_bus_unref = reinterpret_cast<sd_bus_unref_ptr>(
        dlsym(systemd_library, "sd_bus_unref"));

    if (!sd_bus_default_system || !sd_bus_call_method || !sd_bus_flush ||
        !sd_bus_close || !sd_bus_unref) {
      VLOG(1) << "Failed to find the required symbols in libsystemd";
      init_success = false;
    }

  } else {
    VLOG(1) << "Failed to find libsystemd library";
    init_success = false;
  }

  return init_success;
}

bool systemd_is_loaded = loadSystemd();

osquery::Status uidToUsername(std::string& username, uid_t uid) {
  try {
    PasswdEntry user_passwd(uid);
    username = user_passwd.username();
  } catch (const osquery::Status& status) {
    return status;
  }

  return osquery::Status(0);
}

osquery::Status usernameToUid(uid_t& uid, const std::string& username) {
  try {
    PasswdEntry user_passwd(username);
    uid = user_passwd.uid();
  } catch (const osquery::Status& status) {
    return status;
  }

  return osquery::Status(0);
}

osquery::Status parseUid(uid_t& uid, const std::string& str_uid) {
  if (str_uid.empty()) {
    return osquery::Status::failure("Empty uid received");
  }

  char* endptr = nullptr;
  uint64_t user_id = std::strtoul(str_uid.c_str(), &endptr, 10);

  if (user_id > UINT_MAX || errno == ERANGE || *endptr != '\0') {
    errno = 0;
    return osquery::Status(1, "Invalid uid given: " + str_uid);
  }

  uid = static_cast<uid_t>(user_id);

  return osquery::Status(0);
}

osquery::Status validateUserName(const std::string& username) {
  if (username.length() > 32) {
    return osquery::Status::failure("Username too long");
  }

  if (std::find_if(username.begin(),
                   username.end(),
                   static_cast<int (*)(int)>(std::isalnum)) == username.end()) {
    return osquery::Status::failure("Unsafe character found in the username");
  }

  return osquery::Status(0);
}

osquery::Status lockUser(const std::string& username) {
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

osquery::Status logoutUser(const std::string& username, uid_t uid) {
  bool systemd_logout_failed = true;

  if (systemd_is_loaded) {
    int sd_bus_init_error = sd_bus_default_system(&sd_bus_ptr);
    if (sd_bus_init_error >= 0) {
      sd_bus_error bus_error{};
      int call_result = sd_bus_call_method(sd_bus_ptr,
                                           "org.freedesktop.login1",
                                           "/org/freedesktop/login1",
                                           "org.freedesktop.login1.Manager",
                                           "TerminateUser",
                                           &bus_error,
                                           nullptr,
                                           "u",
                                           uid);
      if (call_result < 0) {
        VLOG(1) << "Failed to terminate the user using systemd, error: "
                << bus_error.message;
      } else {
        systemd_logout_failed = false;
      }

      sd_bus_flush(sd_bus_ptr);
      sd_bus_close(sd_bus_ptr);
      sd_bus_unref(sd_bus_ptr);

    } else {
      VLOG(1) << "Failed to initialize a systemd bus, error: "
              << std::to_string(-sd_bus_init_error);
    }
  }

  auto process = std::make_unique<proc_t>();

  if (systemd_logout_failed) {
    PROCTAB* proctab = openproc(PROC_UID, &uid, 1);

    if (proctab == nullptr) {
      return osquery::Status::failure(
          "Unable to kill the user processes, user logout failed");
    }

    while (readproc(proctab, process.get()) != nullptr) {
      kill(process->tid, SIGKILL);
    }

    closeproc(proctab);
  }

  /* TODO: This is necessary because otherwise the systemd process of the user
   * we terminated is still running and the query will exit with error due to
   * the following process scan. Is there a better way?
   */
  sleep(1);

  PROCTAB* proctab = openproc(PROC_UID, &uid, 1);

  if (proctab == nullptr) {
    return osquery::Status::failure(
        "Unable to verify if the user processes have been killed, some "
        "processes might still be running");
  }

  if (readproc(proctab, process.get()) != nullptr) {
    closeproc(proctab);
    return osquery::Status::failure(
        "The user " + std::to_string(uid) +
        " has not been fully logged out, some processes are still running.");
  }
  closeproc(proctab);

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

  try {
    const ShadowFile shadow_file;

    for (const auto& shadow_entry : shadow_file) {
      const PasswdEntry passwd_entry(shadow_entry.username());

      if (!passwd_entry.isEmpty() && (shadow_entry.isPasswordLocked() ||
                                      shadow_entry.accountIsExpired())) {
        locked_users.push_back({passwd_entry.uid(), passwd_entry.username()});
      }
      // TODO: We just ignore non existing users (passwd_entry.isEmpty()) or log
      // them?
    }

  } catch (const osquery::Status& status) {
    return status;
  }

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

  if (document.Size() != 3U) {
    return osquery::Status(1,
                           "Wrong column count " +
                               std::to_string(document.Size()) +
                               " received, 3 expected");
  }

  if (!document[0].IsNull()) {
    row["uid"] = document[0].GetString();
  }

  if (!document[1].IsNull()) {
    row["username"] = document[1].GetString();
  }

  if (!document[2].IsNull()) {
    std::string logout = document[2].GetString();
    boost::to_upper(logout);
    row["logout_user"] = std::move(logout);
  } else {
    row["logout_user"] = "N";
  }

  return osquery::Status(0);
}
} // namespace

osquery::TableColumns BlockedUsersTable::columns() const {
  // clang-format off
  return {
    std::make_tuple("uid", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("username", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("logout_user", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT)
  };
  // clang-format on
}

osquery::QueryData BlockedUsersTable::generate(osquery::QueryContext& request) {
  boost::shared_lock_guard<boost::shared_mutex> passwd_lock(passwd_mutex);

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
  boost::lock_guard<boost::shared_mutex> passwd_lock(passwd_mutex);

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
  uid_t user_id = 0;
  bool convert_username_to_uid = false;

  auto username_it = row.find("username");

  if (username_it == row.end()) {
    const auto& str_user_id = row.at("uid");
    status = parseUid(user_id, str_user_id);

    if (status.ok()) {
      status = uidToUsername(username, user_id);
    }

    if (!status.ok()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message", status.getMessage())}};
    }
  } else {
    username = username_it->second;
    convert_username_to_uid = true;
  }

  status = validateUserName(username);
  if (!status.ok()) {
    return {
        {std::make_pair("status", "failure"),
         std::make_pair("message",
                        "Username validation failed: " + status.getMessage())}};
  }

  if (convert_username_to_uid) {
    status = usernameToUid(user_id, username);

    if (!status.ok()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message", status.getMessage())}};
    }
  }

  if (user_id == 0) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", "root user cannot be locked")}};
  }

  status = lockUser(username);
  if (!status.ok()) {
    return {
        {std::make_pair("status", "failure"),
         std::make_pair("message",
                        "Failed to lock the user: " + status.getMessage())}};
  }

  if (row["logout_user"] == "Y") {
    status = logoutUser(username, user_id);

    if (!status.ok()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair(
                   "message",
                   "Failed to logout the user: " + status.getMessage())}};
    }
  }

  osquery::Row result;
  result["id"] = std::to_string(user_id);
  result["status"] = "success";
  return {result};
}

osquery::QueryData BlockedUsersTable::delete_(
    osquery::QueryContext& context, const osquery::PluginRequest& request) {
  boost::lock_guard<boost::shared_mutex> passwd_lock(passwd_mutex);
  std::string str_user_id = request.at("id");
  uid_t user_id = 0;
  auto status = parseUid(user_id, str_user_id);

  if (!status.ok()) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", status.getMessage())}};
  }

  if (user_id == 0) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", "root user is not a valid uid")}};
  }

  std::string username;
  status = uidToUsername(username, user_id);

  if (!status.ok()) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", status.getMessage())}};
  }

  status = validateUserName(username);
  if (!status.ok()) {
    return {
        {std::make_pair("status", "failure"),
         std::make_pair("message",
                        "Username validation failed: " + status.getMessage())}};
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
