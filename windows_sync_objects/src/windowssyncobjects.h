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

#include <memory>

#include <osquery/sdk/sdk.h>

namespace trailofbits {
class WindowsSyncObjectsTable final : public osquery::TablePlugin {
 public:
  WindowsSyncObjectsTable();
  virtual ~WindowsSyncObjectsTable();

  /// Returns the table schema
  osquery::TableColumns columns() const;

  /// Generates the table rows
  osquery::TableRows generate(osquery::QueryContext& context);

  /// Inserts a new synchronization object into the table
  osquery::QueryData insert(osquery::QueryContext& context,
                            const osquery::PluginRequest& request);

  /// Deletes an existing synchronization object from the table; only objects
  /// created by this extension can be removed
  osquery::QueryData delete_(osquery::QueryContext& context,
                             const osquery::PluginRequest& request);

  /// As updates are not supported, this method returns an error
  osquery::QueryData update(osquery::QueryContext& context,
                            const osquery::PluginRequest& request);

 private:
  struct PrivateData;

  /// Private class data
  std::unique_ptr<PrivateData> d;

  /// Deserializes the JSON data received from osquery
  osquery::Status GetRowData(osquery::Row& row,
                             const std::string& json_value_array);
};
} // namespace trailofbits

// Export the class outside the namespace so that osquery can pick it up
using WindowsSyncObjectsTablePlugin = trailofbits::WindowsSyncObjectsTable;
