/*
 *  Copyright (c) 2017-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <osquery/sdk.h>

class EFIgyTablePlugin final : public osquery::TablePlugin {
 private:
  osquery::TableColumns columns() const override;
  osquery::QueryData generate(osquery::QueryContext& request) override;
};
