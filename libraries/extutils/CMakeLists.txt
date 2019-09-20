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
project(extutils)

function(main)
  set(project_source_files
    include/trailofbits/extutils.h
    src/extutils.cpp
  )

  add_library("${PROJECT_NAME}" STATIC ${project_source_files})
  target_include_directories("${PROJECT_NAME}" PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

  target_link_libraries("${PROJECT_NAME}" PUBLIC
	osquery_cxx_settings
	thirdparty_cxx_settings
	thirdparty_boost
  )

endfunction()

main()
