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

#define EVENTID_SYSENTEREXECVE 0xFF00FF09
#define EVENTID_SYSEXITEXECVE 0xFF00FF0A

#define EVENTID_SYSENTEREXECVEAT 0xFF00FF0B
#define EVENTID_SYSEXITEXECVEAT 0xFF00FF0C

#define MAX_ARGS 11
#define ARG_SIZE 160
#define EVENT_MAP_SIZE 20480

#define VARARGS_TERMINATOR 0xFFFF0000FFFF0000ULL
#define VARARGS_TRUNCATION 0x0011001100110011ULL

#define BOOL int
#define TRUE 1
#define FALSE 0

// clang-format off
#define INCREMENT_EVENT_DATA_INDEX_BY(idx, amount) \
  idx = ((idx + amount) & 0x00FFFFFFUL) % EVENT_MAP_SIZE
// clang-format on

#define INCREMENT_EVENT_DATA_INDEX(idx) INCREMENT_EVENT_DATA_INDEX_BY(idx, 1)
