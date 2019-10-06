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

#pragma once

#include <ctime>
#include <memory>

#if OSQUERY_VERSION_NUMBER >= OSQUERY_SDK_VERSION(4, 0)
#include <osquery/extensions.h>
#else
#include <osquery/flags.h>
#endif

#include <json11.hpp>

namespace trailofbits {
class ConfigurationFile;

/// A reference to a ConfigurationFile object
using ConfigurationFileRef = std::shared_ptr<ConfigurationFile>;

/// A configuration file handle
using ConfigurationFileHandle = std::uint64_t;

/// The configuration file is used to load and monitor a single json-based
/// configuration file
class ConfigurationFile final {
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// Private constructor; use ::create() instead
  ConfigurationFile(const std::string& configuration_file_path);

  /// Reloads the configuration from disk
  void updateConfiguration();

 public:
  /// Factory method
  static osquery::Status create(ConfigurationFileRef& configuration_file,
                                const std::string& configuration_file_path);

  /// Destructor
  ConfigurationFile() = default;

  /// Creates a new handle that can be used to acquire new configurations
  ConfigurationFileHandle getHandle();

  /// Returns true if the configuration has been changed
  bool configurationChanged(ConfigurationFileHandle handle);

  /// Returns the new configuration, if ::configurationChanged() returned true
  json11::Json getConfiguration(ConfigurationFileHandle handle);

  /// Disable the copy constructor
  ConfigurationFile(const ConfigurationFile& other) = delete;

  /// Disable the assignment operator
  ConfigurationFile& operator=(const ConfigurationFile& other) = delete;
};
} // namespace trailofbits
