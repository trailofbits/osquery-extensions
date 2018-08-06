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
project(ntfs_forensics)

function(main)
  set(project_common_source_files
    src/ntfs_types.h

    src/diskdevice.h
    src/diskdevice.cpp

    src/ntfsfileinformation.h
    src/ntfsfileinformation.cpp

    src/ntfsdirectoryindexentry.h
    src/ntfsdirectoryindexentry.cpp

    src/ntfsfilenameattributecontents.h
    src/ntfsfilenameattributecontents.cpp

    src/diskpartition.h
    src/diskpartition.cpp

    src/constraints.h
    src/constraints.cpp
  )

  set(project_include_dirs
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
  )

  add_osquery_extension_ex("NTFSFileInfoTablePlugin" "table" "ntfs_file_data"
    SOURCES ${project_common_source_files} src/ntfsfileinfotable.h src/ntfsfileinfotable.cpp
    INCLUDEDIRS ${project_include_dirs}
    MAININCLUDES ntfsfileinfotable.h
    LIBRARIES tsk_builtin
  )

  add_osquery_extension_ex("NTFSPartInfoTablePlugin" "table" "ntfs_part_data"
    SOURCES ${project_common_source_files} src/ntfspartinfotable.h src/ntfspartinfotable.cpp
    INCLUDEDIRS ${project_include_dirs}
    MAININCLUDES ntfspartinfotable.h
    LIBRARIES tsk_builtin
  )

  add_osquery_extension_ex("NTFSINDXTablePugin" "table" "ntfs_indx_data"
    SOURCES ${project_common_source_files} src/ntfsindxtable.h src/ntfsindxtable.cpp
    INCLUDEDIRS ${project_include_dirs}
    MAININCLUDES ntfsindxtable.h
    LIBRARIES tsk_builtin
  )
endfunction()

main()
