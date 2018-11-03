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

#include <chrono>
#include <iostream>
#include <mutex>
#include <unordered_map>

#include <pubsub/configurationfile.h>

#include <boost/filesystem.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/thread/shared_mutex.hpp>

namespace boostfs = boost::filesystem;

namespace trailofbits {
namespace {
/// Configuration update interval
const std::chrono::milliseconds kConfigurationUpdateInterval{5000};

/// The data associated with an handle; contains the configuration and when it
/// was updated
struct ConfigurationFileHandleInfo final {
  /// Timestamp for this configuration
  std::time_t current_config_timestamp{0U};

  /// Configuration
  json11::Json configuration;
};

/// A reference to a handle data object
using ConfigurationFileHandleInfoRef =
    std::shared_ptr<ConfigurationFileHandleInfo>;

/// Generates a new configuration handle
ConfigurationFileHandle generateHandle() {
  static std::uint64_t handle_generator{0U};
  return handle_generator++;
}
} // namespace

/// Private class data
struct ConfigurationFile::PrivateData final {
  /// Configuration file path
  std::string configuration_file_path;

  /// The modification time of the configuration file
  std::time_t current_config_timestamp{0U};

  /// When the last modification time update has happened
  std::chrono::time_point<std::chrono::system_clock>
      last_configuration_update{};

  /// Mutex used to protect access to the internal variables
  boost::shared_timed_mutex mutex;

  /// Maps handles to their data structures
  std::unordered_map<ConfigurationFileHandle, ConfigurationFileHandleInfoRef>
      handle_map;

  /// Configuration
  json11::Json configuration;
};

ConfigurationFile::ConfigurationFile(const std::string& configuration_file_path)
    : d(new PrivateData) {
  d->configuration_file_path = configuration_file_path;
}

void ConfigurationFile::updateConfiguration() {
  auto current_time = std::chrono::system_clock::now();

  auto next_update_time =
      std::chrono::time_point_cast<std::chrono::milliseconds>(
          d->last_configuration_update) +
      kConfigurationUpdateInterval;

  if (next_update_time >
      std::chrono::time_point_cast<std::chrono::milliseconds>(current_time)) {
    return;
  }

  std::unique_lock<decltype(d->mutex)> lock(d->mutex);
  d->last_configuration_update = current_time;

  auto new_config_timestamp =
      boostfs::last_write_time(d->configuration_file_path);
  if (d->current_config_timestamp == new_config_timestamp) {
    return;
  }

  std::ifstream json_file(d->configuration_file_path);
  std::string json_data((std::istreambuf_iterator<char>(json_file)),
                        std::istreambuf_iterator<char>());

  std::string parsing_errors;
  auto new_configuration = json11::Json::parse(json_data, parsing_errors);
  if (new_configuration == json11::Json()) {
    std::cerr << "The following configuration file is not valid: \""
              << d->configuration_file_path
              << "\". The following error has occurred: " << parsing_errors
              << "\n";
    return;
  }

  d->configuration = std::move(new_configuration);
  d->current_config_timestamp = new_config_timestamp;
}

osquery::Status ConfigurationFile::create(
    ConfigurationFileRef& configuration_file,
    const std::string& configuration_file_path) {
  configuration_file.reset();

  try {
    auto ptr = new ConfigurationFile(configuration_file_path);
    configuration_file.reset(ptr);
    return osquery::Status(0);

  } catch (const std::bad_alloc&) {
    return osquery::Status(1, "Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

ConfigurationFileHandle ConfigurationFile::getHandle() {
  std::unique_lock<decltype(d->mutex)> lock(d->mutex);

  auto handle = generateHandle();
  auto handle_info = std::make_shared<ConfigurationFileHandleInfo>();
  d->handle_map.insert({handle, std::move(handle_info)});

  return handle;
}

bool ConfigurationFile::configurationChanged(ConfigurationFileHandle handle) {
  updateConfiguration();

  ConfigurationFileHandleInfoRef handle_info;
  bool configuration_changed = false;

  {
    boost::upgrade_lock<decltype(d->mutex)> read_lock(d->mutex);

    auto it = d->handle_map.find(handle);
    if (it == d->handle_map.end()) {
      return false;
    }

    handle_info = it->second;

    if (handle_info->current_config_timestamp != d->current_config_timestamp) {
      configuration_changed = true;
      handle_info->configuration = d->configuration;
      handle_info->current_config_timestamp = d->current_config_timestamp;
    }
  }

  return configuration_changed;
}

json11::Json ConfigurationFile::getConfiguration(
    ConfigurationFileHandle handle) {
  boost::upgrade_lock<decltype(d->mutex)> read_lock(d->mutex);

  auto it = d->handle_map.find(handle);
  if (it == d->handle_map.end()) {
    return json11::Json();
  }

  auto handle_info = it->second;
  return handle_info->configuration;
}
} // namespace trailofbits
