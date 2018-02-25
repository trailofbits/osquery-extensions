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

#pragma once

#include <osquery/sdk.h>

namespace trailofbits {
class HostBlacklistTable : public osquery::TablePlugin {
 public:
  osquery::TableColumns columns() const;
  osquery::QueryData generate(osquery::QueryContext& context);

  osquery::QueryData insert(osquery::QueryContext& context,
                            const osquery::PluginRequest& request);
  osquery::QueryData delete_(osquery::QueryContext& context,
                             const osquery::PluginRequest& request);
  osquery::QueryData update(osquery::QueryContext& context,
                            const osquery::PluginRequest& request);
};
} // namespace trailofbits
