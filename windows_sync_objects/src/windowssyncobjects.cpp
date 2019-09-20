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

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

#include <osquery/sdk/sdk.h>

#include <rapidjson/document.h>

#include "objectmanager.h"
#include "windowssyncobjects.h"

namespace trailofbits {
namespace {
using PrimaryKey = std::string;
using RowID = std::uint32_t;
using RowIdToPrimaryKeyMap = std::unordered_map<RowID, PrimaryKey>;

struct ObjectInformation final {
  ObjectDescriptor::Type type;

  union {
    MutantHandle mutant_handle;
    EventHandle event_handle;
    SemaphoreHandle semaphore_handle;
  };
};

RowID GenerateRowID(bool ephemeral) {
  static std::uint32_t generator = 1ULL;

  auto new_id = generator;
  if (ephemeral) {
    new_id |= 0x80000000U;
  } else {
    new_id &= 0x7FFFFFFFU;
  }

  ++generator;
  if (generator == 0) {
    ++generator;
  }

  return static_cast<RowID>(new_id);
}
}

struct WindowsSyncObjectsTable::PrivateData final {
  std::mutex mutex;

  std::unordered_map<std::string, ObjectInformation> path_to_object;
  std::unordered_map<RowID, std::string> rowid_to_path;
};

WindowsSyncObjectsTable::WindowsSyncObjectsTable() : d(new PrivateData) {}

WindowsSyncObjectsTable::~WindowsSyncObjectsTable() {}

osquery::TableColumns WindowsSyncObjectsTable::columns() const {
  // clang-format off
  return {
    std::make_tuple("type", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("path", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("name", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("field1_name", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("field1_value", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("field2_name", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("field2_value", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("field3_name", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    std::make_tuple("field3_value", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT)
  };
  // clang-format on
}

osquery::TableRows WindowsSyncObjectsTable::generate(osquery::QueryContext&) {
  std::lock_guard<std::mutex> lock(d->mutex);

  struct CallbackData final {
    std::unordered_map<RowID, std::string>& rowid_to_path;
    const std::unordered_set<ObjectDescriptor::Type>& filter;
    osquery::QueryData results;
  };

  auto L_enumObObjectsCallback = [](const ObjectDescriptor& object_descriptor,
                                    void* user_defined) -> bool {
    auto& callback_data = *static_cast<CallbackData*>(user_defined);
    if (callback_data.filter.count(object_descriptor.type) == 0) {
      return true;
    }

    // Restore the original rowid if we have created this object ourselves
    auto full_path = object_descriptor.path + "\\" + object_descriptor.name;

    // clang-format off
    auto user_object_it = std::find_if(
      callback_data.rowid_to_path.begin(),
      callback_data.rowid_to_path.end(),
      [full_path](const std::pair<RowID, std::string> &p) -> bool {
        return (full_path == p.second);
      }
    );
    // clang-format on

    osquery::Row row;
    if (user_object_it == callback_data.rowid_to_path.end()) {
      row["rowid"] = std::to_string(GenerateRowID(true));
    } else {
      row["rowid"] = std::to_string(user_object_it->first);
    }

    row["path"] = object_descriptor.path;
    row["name"] = object_descriptor.name;

    switch (object_descriptor.type) {
    case ObjectDescriptor::Type::Event: {
      row["type"] = "Event";

      row["field1_name"] = "EventType";
      switch (object_descriptor.event_data.type) {
      case ObjectDescriptor::EventData::Type::NotificationEvent: {
        row["field1_value"] = "Notification";
        break;
      }

      case ObjectDescriptor::EventData::Type::SynchronizationEvent: {
        row["field1_value"] = "Synchronization";
        break;
      }

      case ObjectDescriptor::EventData::Type::Unknown:
      default: { row["field1_value"] = "Unknown"; }
      }

      row["field2_name"] = "Signaled";
      row["field2_value"] =
          (object_descriptor.event_data.signaled ? "true" : "false");

      row["field3_name"] = row["field3_value"] = "";
      break;
    }

    case ObjectDescriptor::Type::Mutant: {
      row["type"] = "Mutant";

      row["field1_name"] = "CurrentCount";
      row["field1_value"] =
          std::to_string(object_descriptor.mutant_data.current_count);

      row["field2_name"] = "OwnedByCaller";
      row["field2_value"] =
          object_descriptor.mutant_data.owned_by_caller ? "true" : "false";

      row["field3_name"] = "AbandonedState";
      row["field3_value"] =
          object_descriptor.mutant_data.abandoned_state ? "true" : "false";
      break;
    }

    case ObjectDescriptor::Type::Semaphore: {
      row["type"] = "Semaphore";

      row["field1_name"] = "CurrentCount";
      row["field1_value"] =
          std::to_string(object_descriptor.semaphore_data.current_count);

      row["field2_name"] = "MaximumCount";
      row["field2_value"] =
          std::to_string(object_descriptor.semaphore_data.maximum_count);

      row["field3_name"] = row["field3_value"] = "";
      break;
    }

    default: {
      row["type"] = "Unknown";

      row["field1_name"] = row["field1_value"] = "";
      row["field2_name"] = row["field2_value"] = "";
      row["field3_name"] = row["field3_value"] = "";

      break;
    }
    }

    callback_data.results.push_back(osquery::TableRowHolder(new osquery::DynamicTableRow(std::move(row))));
    return true;
  };

  static const std::unordered_set<ObjectDescriptor::Type> filter = {
      ObjectDescriptor::Type::Event,
      ObjectDescriptor::Type::Mutant,
      ObjectDescriptor::Type::Semaphore};

  CallbackData callback_data = {d->rowid_to_path, filter, {}};
  EnumObObjects(L_enumObObjectsCallback, &callback_data);

  return callback_data.results;
}

osquery::QueryData WindowsSyncObjectsTable::insert(
    osquery::QueryContext&, const osquery::PluginRequest& request) {
  std::lock_guard<std::mutex> lock(d->mutex);

  osquery::Row row;
  auto status = GetRowData(row, request.at("json_value_array"));
  if (!status.ok()) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", status.getMessage())}};
  }

  ObjectInformation object_information;

  if (row["type"] == "Mutant") {
    MutantHandle mutant;
    status = GenerateMutant(mutant, row["path"], row["name"]);
    if (!status.ok()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message", status.getMessage())}};
    }

    object_information.type = ObjectDescriptor::Type::Mutant;
    object_information.mutant_handle = mutant;

  } else if (row["type"] == "Event") {
    EventType event_type = (row["field1_value"] == "Notification")
                               ? EventType::Notification
                               : EventType::Synchronization;

    EventHandle event;
    status = GenerateEvent(event, row["path"], row["name"], event_type);
    if (!status.ok()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message", status.getMessage())}};
    }

    object_information.type = ObjectDescriptor::Type::Event;
    object_information.event_handle = event;

  } else if (row["type"] == "Semaphore") {
    SemaphoreHandle semaphore;
    status = GenerateSemaphore(semaphore, row["path"], row["name"]);
    if (!status.ok()) {
      return {{std::make_pair("status", "failure"),
               std::make_pair("message", status.getMessage())}};
    }

    object_information.type = ObjectDescriptor::Type::Semaphore;
    object_information.semaphore_handle = semaphore;

  } else {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", "Invalid entity type")}};
  }

  auto path = row["path"] + "\\" + row["name"];
  d->path_to_object.insert({path, object_information});

  auto row_id = GenerateRowID(false);
  d->rowid_to_path.insert({row_id, path});

  osquery::Row result;
  result["id"] = std::to_string(row_id);
  result["status"] = "success";
  return {result};
}

osquery::QueryData WindowsSyncObjectsTable::delete_(
    osquery::QueryContext&, const osquery::PluginRequest& request) {
  std::lock_guard<std::mutex> lock(d->mutex);

  char* null_term_ptr = nullptr;
  auto row_id = static_cast<std::uint32_t>(
      std::strtoul(request.at("id").c_str(), &null_term_ptr, 10));
  if (*null_term_ptr != 0) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", "Invalid row id received")}};
  }

  // We only support editing of our own objects
  if ((row_id & 0x80000000U) != 0) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message",
                            "The specified object is not owned by osquery")}};
  }

  auto path_it = d->rowid_to_path.find(row_id);
  if (path_it == d->rowid_to_path.end()) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", "Row id not found")}};
  }

  auto object_it = d->path_to_object.find(path_it->second);
  if (object_it == d->path_to_object.end()) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", "Row id -> path mismatch")}};
  }

  auto object_information = object_it->second;
  bool succeeded = false;

  switch (object_information.type) {
  case ObjectDescriptor::Type::Mutant: {
    succeeded = DestroyMutant(object_information.mutant_handle);
    break;
  }

  case ObjectDescriptor::Type::Event: {
    succeeded = DestroyEvent(object_information.event_handle);
    break;
  }

  case ObjectDescriptor::Type::Semaphore: {
    succeeded = DestroySemaphore(object_information.event_handle);
    break;
  }

  default: { break; }
  }

  if (!succeeded) {
    return {{std::make_pair("status", "failure"),
             std::make_pair("message", "Failed to destroy the object")}};
  }

  d->rowid_to_path.erase(path_it);
  d->path_to_object.erase(object_it);

  return {{std::make_pair("status", "success")}};
}

osquery::QueryData WindowsSyncObjectsTable::update(
    osquery::QueryContext&, const osquery::PluginRequest&) {
  return {{std::make_pair("status", "failure"),
           std::make_pair("message", "This operation is not supported")}};
}

osquery::Status WindowsSyncObjectsTable::GetRowData(
    osquery::Row& row, const std::string& json_value_array) {
  row.clear();
  json_value_array.size();

  rapidjson::Document document;
  document.Parse(json_value_array);
  if (document.HasParseError() || !document.IsArray()) {
    return osquery::Status(1, "Invalid format");
  }

  if (document.Size() != 9U) {
    return osquery::Status(1, "Wrong column count");
  }

  // We only need three fields: type, path, name
  if (document[0].IsNull()) {
    return osquery::Status(1, "Type is missing");
  }

  if (document[1].IsNull()) {
    return osquery::Status(1, "Path is missing");
  }

  if (document[2].IsNull()) {
    return osquery::Status(1, "Name is missing");
  }

  row["type"] = document[0].GetString();
  row["path"] = document[1].GetString();
  row["name"] = document[2].GetString();

  if (row["type"] != "Event" && row["type"] != "Mutant" &&
      row["type"] != "Semaphore") {
    return osquery::Status(1, "Invalid type");
  }

  // Events need a subtype
  if (row["type"] == "Event") {
    if (document[4].IsNull()) {
      return osquery::Status(1, "The event type is missing");
    }

    row["field1_value"] = document[4].GetString();
    if (row["field1_value"].empty()) {
      return osquery::Status(1, "The event type is empty");
    }

    if (row["field1_value"] != "Notification" &&
        row["field1_value"] != "Synchronization") {
      return osquery::Status(1, "The event type is not valid");
    }
  }

  return osquery::Status(0, "OK");
}
} // namespace trailofbits
