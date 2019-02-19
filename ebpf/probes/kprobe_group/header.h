/*
 * Copyright (c) 2019-present Trail of Bits, Inc.
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

#define BASE_CALL_IDENTIFIER 0x8000000000000000ULL

#define KPROBE_PIDVNR_CALL (BASE_CALL_IDENTIFIER | 1ULL)
#define KPROBE_FORK_CALL (BASE_CALL_IDENTIFIER | 2ULL)
#define KPROBE_VFORK_CALL (BASE_CALL_IDENTIFIER | 3ULL)
#define KPROBE_CLONE_CALL (BASE_CALL_IDENTIFIER | 4ULL)
