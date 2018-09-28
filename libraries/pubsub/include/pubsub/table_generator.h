#pragma once

#include "eventbufferlibrary.h"

#include <osquery/sdk.h>

// clang-format off
#define BEGIN_TABLE(name) \
  class name ## TablePlugin final : public osquery::TablePlugin { \
   public: \
    name ## TablePlugin() = default; \
    ~name ## TablePlugin() = default; \
    \
    osquery::QueryData generate(osquery::QueryContext& request) override { \
      return EventBufferLibrary::instance().getEvents(#name); \
    } \
    \
    osquery::TableColumns columns() const override { \
      static const osquery::TableColumns schema = {
// clang-format on

// clang-format off
#define TABLE_COLUMN(name, type) \
  std::make_tuple(#name, type, osquery::ColumnOptions::DEFAULT),
// clang-format on

// clang-format off
#define END_TABLE(name) \
      }; \
      return schema; \
    } \
  }; \
  \
  REGISTER_EXTERNAL(name ## TablePlugin, "table", #name);
// clang-format on
