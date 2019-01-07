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

#define EVENTID_SYSENTERCREAT 0xFF00FF0D
#define EVENTID_SYSENTERMKNOD 0xFF00FF0E
#define EVENTID_SYSENTERMKNODAT 0xFF00FF0F
#define EVENTID_SYSENTEROPEN 0xFF00FF10
#define EVENTID_SYSENTEROPENAT 0xFF00FF11
#define EVENTID_SYSENTEROPEN_BY_HANDLE_AT 0xFF00FF12
#define EVENTID_SYSENTERNAME_TO_HANDLE_AT 0xFF00FF13
#define EVENTID_SYSENTERCLOSE 0xFF00FF14
#define EVENTID_SYSENTERDUP 0xFF00FF15
#define EVENTID_SYSENTERDUP2 0xFF00FF16
#define EVENTID_SYSENTERDUP3 0xFF00FF17
#define EVENTID_SYSENTERSOCKET 0xFF00FF18
#define EVENTID_SYSENTERSOCKETPAIR 0xFF00FF19

#define ARG_SIZE 160
#define EVENT_MAP_SIZE 1000000

// clang-format off
#define INCREMENT_EVENT_DATA_INDEX_BY(idx, amount) \
  idx = ((idx + amount) & 0x00FFFFFFUL) % EVENT_MAP_SIZE
// clang-format on

// clang-format off
#define INCREMENT_EVENT_DATA_INDEX(idx) \
  INCREMENT_EVENT_DATA_INDEX_BY(idx, 1)
// clang-format on
