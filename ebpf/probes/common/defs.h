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

/// The size of the per-CPU map used to store events
#define EVENT_MAP_SIZE 1000000

/// The terminator used by StringList types
#define VARARGS_TERMINATOR 0xFFFF0000FFFF0000ULL

/// The truncation ID used by StringList types
#define VARARGS_TRUNCATION 0x0011001100110011ULL

/// Base event type
#define BASE_EVENT_TYPE 0x1122334455660000ULL

// clang-format off
#define INCREMENT_EVENT_DATA_INDEX_BY(idx, amount) \
  idx = ((idx + amount) & 0x00FFFFFFUL) % EVENT_MAP_SIZE
// clang-format on

// clang-format off
#define INCREMENT_EVENT_DATA_INDEX(idx) \
  INCREMENT_EVENT_DATA_INDEX_BY(idx, 1)
// clang-format on
