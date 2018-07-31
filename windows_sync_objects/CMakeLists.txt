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
project(windows_sync_objects)

function(main)
  set(project_common_source_files
    src/winapi.h
    src/objectmanager.h
    src/objectmanager.cpp

    src/basetable.h
    src/windowssyncobjects.cpp
  )

  set(project_include_dirs
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
  )

  add_osquery_extension_ex("WindowsSyncObjectsTablePlugin" "table" "windows_sync_objects"
    SOURCES ${project_common_source_files}
    INCLUDEDIRS ${project_include_dirs}
    MAININCLUDES windowssyncobjects.h
    LIBRARIES
  )

endfunction()

main()
