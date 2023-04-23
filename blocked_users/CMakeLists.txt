# Copyright (c) 2018 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.10)
project(blocked_users)

function(blockedUsersMain)
  set(source_files
    src/blockeduserstable.h
    src/blockeduserstable.cpp
    src/passwdentry.cpp
    src/passwdentry.h
    src/shadowfile.cpp
    src/shadowfile.h
    src/shadowentry.cpp
    src/shadowentry.h
  )

  add_osquery_extension_ex("BlockedUsersTable" "table" "blocked_users"
    SOURCES ${source_files}
    INCLUDEDIRS "${CMAKE_CURRENT_SOURCE_DIR}/src" ${project_include_folders}
    MAININCLUDES blockeduserstable.h
  )
endfunction()

blockedUsersMain()
