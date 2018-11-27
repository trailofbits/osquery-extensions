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

#define EVENTID_SYSENTERCLONE 0xFF00FF00
#define EVENTID_SYSEXITCLONE 0xFF00FF01

#define EVENTID_SYSENTERFORK 0xFF00FF02
#define EVENTID_SYSEXITFORK 0xFF00FF03

#define EVENTID_SYSENTERVFORK 0xFF00FF04
#define EVENTID_SYSEXITVFORK 0xFF00FF05

#define EVENTID_PIDVNR 0xFF00FF06

#define EVENTID_SYSENTEREXIT 0xFF00FF07
#define EVENTID_SYSENTEREXITGROUP 0xFF00FF08

#define EVENT_MAP_SIZE 20480

#define BOOL int
#define TRUE 1
#define FALSE 0

// clang-format off
#define INCREMENT_EVENT_DATA_INDEX_BY(idx, amount) \
  idx = ((idx + amount) & 0x00FFFFFFUL) % EVENT_MAP_SIZE
// clang-format on

#define INCREMENT_EVENT_DATA_INDEX(idx) INCREMENT_EVENT_DATA_INDEX_BY(idx, 1)
