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

#include "objectmanager.h"
#include "winapi.h" // Definitions for undocumented Windows APIs

#include "osquery/core/windows/wmi.h" // We need this for wstringToString
#include <osquery/logger.h>

#include <array>
#include <cstdint>
#include <sstream>
#include <vector>

namespace {
struct DirectoryEntry final {
  std::wstring name;
  std::wstring type;
};
}

namespace trailofbits {
std::string GetErrorMessage(ULONG error_code) {
  std::stringstream message;

  char* buffer = nullptr;
  if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |
                         FORMAT_MESSAGE_ALLOCATE_BUFFER |
                         FORMAT_MESSAGE_IGNORE_INSERTS,
                     nullptr,
                     error_code,
                     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                     reinterpret_cast<LPSTR>(&buffer),
                     0U,
                     nullptr) == 0 ||
      buffer == nullptr) {
    message << std::hex << error_code;

  } else {
    message << buffer << " (0x" << std::hex << error_code << ")";
    LocalFree(buffer);
  }

  return message.str();
}

void ListObDirectoryObjectsHelper(std::vector<DirectoryEntry>& entry_list,
                                  HANDLE directory) {
  entry_list.clear();

  std::array<std::uint8_t, 4096> buffer;
  ULONG entry_index = 0U;

  while (true) {
    ULONG response_size = 0U;
    std::memset(buffer.data(), static_cast<int>(buffer.size()), 0);

    auto status = NtQueryDirectoryObject(directory,
                                         buffer.data(),
                                         static_cast<ULONG>(buffer.size()),
                                         FALSE,
                                         entry_list.empty() ? TRUE : FALSE,
                                         &entry_index,
                                         &response_size);
    if (NT_ERROR(status)) {
      auto error_code = RtlNtStatusToDosError(status);
      VLOG(1) << "Directory query failed with the following error: "
              << GetErrorMessage(error_code);
      break;
    }

    auto directory_entries =
        reinterpret_cast<const OBJECT_DIRECTORY_INFORMATION*>(buffer.data());

    for (std::size_t i = 0U; directory_entries[i].Name.Length != 0; i++) {
      DirectoryEntry entry = {directory_entries[i].Name.Buffer,
                              directory_entries[i].TypeName.Buffer};

      entry_list.push_back(entry);
    }

    if (status != STATUS_MORE_ENTRIES) {
      break;
    }
  };
}

bool QueryObObjectInformation(ObjectDescriptor& object_descriptor,
                              const std::wstring& directory_path,
                              const std::wstring& name,
                              const std::wstring& type) {
  object_descriptor = {};

  static const auto filter = {L"Event", L"Mutant", L"Semaphore"};
  auto filter_it = std::find(filter.begin(), filter.end(), type);
  if (filter_it == filter.end()) {
    return false;
  }

  std::wstring full_path = directory_path + L"\\" + name;
  object_descriptor.path = osquery::wstringToString(directory_path.data());
  object_descriptor.name = osquery::wstringToString(name.data());

  UNICODE_STRING object_path = {};
  RtlInitUnicodeString(&object_path, full_path.data());

  OBJECT_ATTRIBUTES object_attributes = {};
  InitializeObjectAttributes(
      &object_attributes, &object_path, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

  if (type == L"Event") {
    object_descriptor.type = ObjectDescriptor::Type::Event;

    HANDLE object;
    auto status = NtOpenEvent(&object, EVENT_QUERY_STATE, &object_attributes);
    if (status < 0) {
      return false;
    }

    EVENT_BASIC_INFORMATION event_information = {};
    status = NtQueryEvent(object,
                          EventBasicInformation,
                          &event_information,
                          sizeof(event_information),
                          nullptr);

    CloseHandle(object);
    if (NT_ERROR(status)) {
      return false;
    }

    ObjectDescriptor::EventData event_data = {};
    event_data.signaled = event_information.EventState != 0;

    switch (event_information.EventType) {
    case NotificationEvent: {
      event_data.type = ObjectDescriptor::EventData::Type::NotificationEvent;
      break;
    }

    case SynchronizationEvent: {
      event_data.type = ObjectDescriptor::EventData::Type::SynchronizationEvent;
      break;
    }

    default: {
      event_data.type = ObjectDescriptor::EventData::Type::Unknown;
      break;
    }
    }

    object_descriptor.event_data = event_data;

  } else if (type == L"Mutant") {
    object_descriptor.type = ObjectDescriptor::Type::Mutant;

    HANDLE object;
    auto status = NtOpenMutant(&object, MUTANT_QUERY_STATE, &object_attributes);
    if (status < 0) {
      return false;
    }

    MUTANT_BASIC_INFORMATION mutant_information = {};
    status = NtQueryMutant(object,
                           MutantBasicInformation,
                           &mutant_information,
                           sizeof(mutant_information),
                           nullptr);

    CloseHandle(object);
    if (NT_ERROR(status)) {
      return false;
    }

    ObjectDescriptor::MutantData mutant_data = {
        static_cast<std::int32_t>(mutant_information.CurrentCount),
        mutant_information.OwnedByCaller == TRUE,
        mutant_information.AbandonedState == TRUE};

    object_descriptor.mutant_data = mutant_data;

  } else if (type == L"Semaphore") {
    object_descriptor.type = ObjectDescriptor::Type::Semaphore;

    HANDLE object;
    auto status =
        NtOpenSemaphore(&object, SEMAPHORE_QUERY_STATE, &object_attributes);

    if (status < 0) {
      return false;
    }

    SEMAPHORE_BASIC_INFORMATION semaphore_information = {};
    status = NtQuerySemaphore(object,
                              SemaphoreBasicInformation,
                              &semaphore_information,
                              sizeof(semaphore_information),
                              nullptr);

    CloseHandle(object);
    if (NT_ERROR(status)) {
      return false;
    }

    ObjectDescriptor::SemaphoreData semaphore_data = {
        static_cast<std::uint32_t>(semaphore_information.CurrentCount),
        static_cast<std::uint32_t>(semaphore_information.MaximumCount)};

    object_descriptor.semaphore_data = semaphore_data;
  }

  return true;
}

bool ListObDirectoryObjects(std::vector<DirectoryEntry>& directory_entries,
                            const std::wstring& path) {
  UNICODE_STRING directory_path = {};
  RtlInitUnicodeString(&directory_path, path.data());

  OBJECT_ATTRIBUTES directory_attributes = {};
  InitializeObjectAttributes(&directory_attributes,
                             &directory_path,
                             OBJ_CASE_INSENSITIVE,
                             nullptr,
                             nullptr);

  HANDLE directory_handle = nullptr;
  auto status = NtOpenDirectoryObject(&directory_handle,
                                      DIRECTORY_TRAVERSE | DIRECTORY_QUERY,
                                      &directory_attributes);

  bool succeeded = false;
  if (NT_ERROR(status)) {
    auto error_code = RtlNtStatusToDosError(status);

    VLOG(1) << "Failed to open the following directory object: "
            << osquery::wstringToString(path.data())
            << ". Error: " << GetErrorMessage(error_code);

  } else {
    succeeded = true;
    ListObDirectoryObjectsHelper(directory_entries, directory_handle);
  }

  CloseHandle(directory_handle);
  return succeeded;
}

void EnumObObjects(EnumObObjectsCallback callback, void* user_defined) {
  std::vector<std::wstring> pending_directory_queue = {L"\\"};

  while (!pending_directory_queue.empty()) {
    auto current_directory_path = pending_directory_queue.back();
    pending_directory_queue.pop_back();

    std::vector<DirectoryEntry> directory_entries;
    if (!ListObDirectoryObjects(directory_entries, current_directory_path)) {
      continue;
    }

    for (const auto& entry : directory_entries) {
      ObjectDescriptor object_descriptor = {};
      if (QueryObObjectInformation(object_descriptor,
                                   current_directory_path.data(),
                                   entry.name.data(),
                                   entry.type.data())) {
        if (!callback(object_descriptor, user_defined)) {
          break;
        }
      }

      if (entry.type == L"Directory") {
        auto next_path =
            current_directory_path +
            (current_directory_path.back() == L'\\' ? L"" : L"\\") + entry.name;

        pending_directory_queue.push_back(next_path);
      }
    }
  }
}

osquery::Status GenerateMutant(MutantHandle& handle,
                               const std::string& path,
                               const std::string& name) {
  std::wstring path_str = osquery::stringToWstring(path.data()) + L"\\" +
                          osquery::stringToWstring(name.data());

  UNICODE_STRING path_obj = {};
  RtlInitUnicodeString(&path_obj, path_str.data());

  OBJECT_ATTRIBUTES attributes = {};
  InitializeObjectAttributes(
      &attributes, &path_obj, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

  HANDLE mutant;
  auto status = NtCreateMutant(&mutant, MUTANT_ALL_ACCESS, &attributes, TRUE);
  if (NT_ERROR(status)) {
    std::stringstream message;
    message << "NtCreateMutant failed with error 0x" << std::hex << status;

    return osquery::Status(1, message.str());
  }

  handle = static_cast<MutantHandle>(mutant);
  return osquery::Status(0);
}

bool DestroyMutant(MutantHandle handle) {
  auto mutant = static_cast<HANDLE>(handle);
  return (CloseHandle(mutant) != 0);
}

osquery::Status GenerateEvent(EventHandle& handle,
                              const std::string& path,
                              const std::string& name,
                              EventType type) {
  std::wstring path_str = osquery::stringToWstring(path.data()) + L"\\" +
                          osquery::stringToWstring(name.data());

  UNICODE_STRING path_obj = {};
  RtlInitUnicodeString(&path_obj, path_str.data());

  OBJECT_ATTRIBUTES attributes = {};
  InitializeObjectAttributes(
      &attributes, &path_obj, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

  HANDLE event;
  auto status =
      NtCreateEvent(&event,
                    EVENT_ALL_ACCESS,
                    &attributes,
                    (type == EventType::Notification) ? NotificationEvent
                                                      : SynchronizationEvent,
                    TRUE);
  if (NT_ERROR(status)) {
    std::stringstream message;
    message << "NtCreateEvent failed with error 0x" << std::hex << status;

    return osquery::Status(1, message.str());
  }

  handle = static_cast<EventHandle>(event);
  return osquery::Status(0);
}

bool DestroyEvent(EventHandle handle) {
  auto event = static_cast<HANDLE>(handle);
  return (CloseHandle(event) != 0);
}

osquery::Status GenerateSemaphore(SemaphoreHandle& handle,
                                  const std::string& path,
                                  const std::string& name) {
  std::wstring path_str = osquery::stringToWstring(path.data()) + L"\\" +
                          osquery::stringToWstring(name.data());

  UNICODE_STRING path_obj = {};
  RtlInitUnicodeString(&path_obj, path_str.data());

  OBJECT_ATTRIBUTES attributes = {};
  InitializeObjectAttributes(
      &attributes, &path_obj, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

  HANDLE semaphore;
  auto status =
      NtCreateSemaphore(&semaphore, SEMAPHORE_ALL_ACCESS, &attributes, 1, 1);

  if (NT_ERROR(status)) {
    std::stringstream message;
    message << "NtCreateSemaphore failed with error 0x" << std::hex << status;

    return osquery::Status(1, message.str());
  }

  handle = static_cast<SemaphoreHandle>(semaphore);
  return osquery::Status(0);
}

bool DestroySemaphore(SemaphoreHandle handle) {
  auto semaphore = static_cast<HANDLE>(handle);
  return (CloseHandle(semaphore) != 0);
}
}