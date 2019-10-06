#pragma once

#include "eventbufferlibrary.h"

#if OSQUERY_VERSION_NUMBER < OSQUERY_SDK_VERSION(4, 0)
#include <osquery/sdk.h>
#else
#include <osquery/sdk/sdk.h>
#endif

// clang-format off
#define BEGIN_TABLE(name) \
  class name ## TablePlugin final : public osquery::TablePlugin { \
   public: \
    name ## TablePlugin() = default; \
    virtual ~name ## TablePlugin() override; \
    \
	virtual osquery::TableRows generate(osquery::QueryContext&) override { \
      return EventBufferLibrary::instance().getEvents(#name); \
    } \
    \
    virtual osquery::TableColumns columns() const override { \
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
  name ## TablePlugin::~name ## TablePlugin() {}; \
  \
  REGISTER_EXTERNAL(name ## TablePlugin, "table", #name)
// clang-format on
