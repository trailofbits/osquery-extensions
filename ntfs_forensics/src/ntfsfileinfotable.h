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

#include <map>
#include <string>

#include <osquery/sdk.h>

namespace trailofbits {
/// This is the table plugin for ntfs_file_data
class NTFSFileInfoTablePlugin final : public osquery::TablePlugin {
 public:
  /// Returns the table schema
  osquery::TableColumns columns() const override;

  /// Generates the partition list
  osquery::QueryData generate(osquery::QueryContext& request) override;
};
}

// Export the class outside the namespace so that osquery can pick it up
using NTFSFileInfoTablePlugin = trailofbits::NTFSFileInfoTablePlugin;
