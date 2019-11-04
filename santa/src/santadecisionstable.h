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

#if OSQUERY_VERSION_NUMBER < SDK_VERSION(4, 0)
#include <osquery/sdk.h>
#else
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>
#endif

#include "santa.h"

class SantaAllowedDecisionsTablePlugin final : public osquery::TablePlugin {
 private:
  static const SantaDecisionType decision = kAllowed;
  osquery::TableColumns columns() const override;

  osquery::TableRows generate(osquery::QueryContext& request) override;
};

class SantaDeniedDecisionsTablePlugin final : public osquery::TablePlugin {
 private:
  static const SantaDecisionType decision = kDenied;
  osquery::TableColumns columns() const override;

  osquery::TableRows generate(osquery::QueryContext& request) override;
};
