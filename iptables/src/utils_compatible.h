
#pragma once

#include "Version.h"

#if OSQUERY_VERSION_NUMBER < SDK_VERSION(4, 0)
namespace osquery {
  using TableRows = QueryData;
}

static inline void insertRow(osquery::QueryData &result, osquery::Row &row) {
  result.push_back(row);
}
#else
static inline void insertRow(osquery::TableRows &result, osquery::Row &row) {
  result.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(row))));
}
#endif
