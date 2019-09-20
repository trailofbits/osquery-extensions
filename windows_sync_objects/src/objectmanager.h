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

#include <string>

#include <osquery/sdk/sdk.h>

namespace trailofbits {
struct ObjectDescriptor final {
  enum class Type { Semaphore, Mutant, Event };

  struct EventData final {
    enum class Type { Unknown, NotificationEvent, SynchronizationEvent };

    Type type;
    bool signaled;
  };

  struct MutantData final {
    std::int32_t current_count;
    bool owned_by_caller;
    bool abandoned_state;
  };

  struct SemaphoreData final {
    std::uint32_t current_count;
    std::uint32_t maximum_count;
  };

  std::string path;
  std::string name;
  Type type;

  union {
    EventData event_data;
    MutantData mutant_data;
    SemaphoreData semaphore_data;
  };
};

using MutantHandle = void*;
using SemaphoreHandle = void*;
using EventHandle = void*;

using EnumObObjectsCallback =
    bool (*)(const ObjectDescriptor& object_descriptor, void* user_defined);

enum class EventType { Notification, Synchronization };

void EnumObObjects(EnumObObjectsCallback callback, void* user_defined);

osquery::Status GenerateMutant(MutantHandle& handle,
                               const std::string& path,
                               const std::string& name);

bool DestroyMutant(MutantHandle handle);

osquery::Status GenerateEvent(EventHandle& handle,
                              const std::string& path,
                              const std::string& name,
                              EventType type);

bool DestroyEvent(EventHandle handle);

osquery::Status GenerateSemaphore(SemaphoreHandle& handle,
                                  const std::string& path,
                                  const std::string& name);

bool DestroySemaphore(SemaphoreHandle handle);
}
