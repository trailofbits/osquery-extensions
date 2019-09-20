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
project("traiofbits_extensions")

###################################################
##       utilities.cmake
###################################################

# This function takes the global properties saved by add_osquery_extension_ex and generates
# a single extenion executable containing all the user code
function(generate_osquery_extension_group)
  get_property(extension_source_files GLOBAL PROPERTY OSQUERY_EXTENSION_GROUP_SOURCES)
  if("${extension_source_files}" STREQUAL "")
    return()
  endif()

  # Allow the user to customize the extension name and version using
  # environment variables
  if(DEFINED ENV{OSQUERY_EXTENSION_GROUP_NAME})
    set(OSQUERY_EXTENSION_GROUP_NAME $ENV{OSQUERY_EXTENSION_GROUP_NAME})
  else()
    set(OSQUERY_EXTENSION_GROUP_NAME "osquery_extension_group")
  endif()

  if(DEFINED ENV{OSQUERY_EXTENSION_GROUP_VERSION})
    set(OSQUERY_EXTENSION_GROUP_VERSION $ENV{OSQUERY_EXTENSION_GROUP_VERSION})
  else()
    set(OSQUERY_EXTENSION_GROUP_VERSION "1.0")
  endif()

  # Build the include list; this contains the files required to declare
  # the classes used in the REGISTER_EXTERNAL directives
  #
  # Note: The variables in uppercase are used by the template
  get_property(main_include_list GLOBAL PROPERTY OSQUERY_EXTENSION_GROUP_MAIN_INCLUDES)
  foreach(include_file ${main_include_list})
    set(OSQUERY_EXTENSION_GROUP_INCLUDES "${OSQUERY_EXTENSION_GROUP_INCLUDES}\n#include <${include_file}>")
  endforeach()

  # We need to generate the main.cpp file, containing all the required
  # REGISTER_EXTERNAL directives
  get_property(OSQUERY_EXTENSION_GROUP_INITIALIZERS GLOBAL PROPERTY OSQUERY_EXTENSION_GROUP_INITIALIZERS)
  configure_file(
    "${CMAKE_SOURCE_DIR}/tools/codegen/templates/osquery_extension_group_main.cpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/osquery_extension_group_main.cpp"
  )

  # Extensions can no longer control which compilation flags to use here (as they are shared) so
  # we are going to enforce sane defaults
  if(UNIX)
    set(extension_cxx_flags
      -pedantic -Wall -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization
      -Wformat=2 -Winit-self -Wlong-long -Wmissing-declarations -Wmissing-include-dirs -Wcomment
      -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion
      -Wsign-promo -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wunused -Wuninitialized
      -Wconversion -DBOOST_ASIO_DISABLE_STD_STRING_VIEW
    )

    if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
      list(APPEND extension_cxx_flags -g3 -gdwarf-2)
    endif()
  else()
    set(extension_cxx_flags /W4)
  endif()

  # Generate the extension target
  add_executable("${OSQUERY_EXTENSION_GROUP_NAME}"
    "${CMAKE_CURRENT_BINARY_DIR}/osquery_extension_group_main.cpp"
    ${extension_source_files}
  )

  set_property(TARGET "${OSQUERY_EXTENSION_GROUP_NAME}" PROPERTY INCLUDE_DIRECTORIES "")
  target_compile_features("${OSQUERY_EXTENSION_GROUP_NAME}" PUBLIC cxx_std_14)
  target_compile_options("${OSQUERY_EXTENSION_GROUP_NAME}" PRIVATE ${extension_cxx_flags})

  target_link_libraries("${OSQUERY_EXTENSION_GROUP_NAME}" PUBLIC
  	osquery_cxx_settings
  	osquery_sdk_pluginsdk
  	osquery_extensions_implthrift
	thirdparty_boost
	thirdparty_libiptc
  )

  set_target_properties("${OSQUERY_EXTENSION_GROUP_NAME}" PROPERTIES
    OUTPUT_NAME "${OSQUERY_EXTENSION_GROUP_NAME}.ext"
  )

  # Import the core libraries; note that we are going to inherit include directories
  # with the wrong scope, so we'll have to fix it
  set_property(TARGET "${OSQUERY_EXTENSION_GROUP_NAME}" PROPERTY INCLUDE_DIRECTORIES "")

#  get_property(include_folder_list TARGET libosquery PROPERTY INCLUDE_DIRECTORIES)
  target_include_directories("${OSQUERY_EXTENSION_GROUP_NAME}" SYSTEM PRIVATE ${include_folder_list})

#  TARGET_OSQUERY_LINK_WHOLE("${OSQUERY_EXTENSION_GROUP_NAME}" libosquery)

  # Apply the user (extension) settings
  get_property(library_list GLOBAL PROPERTY OSQUERY_EXTENSION_GROUP_LIBRARIES)
  if(NOT "${library_list}" STREQUAL "")
    target_link_libraries("${OSQUERY_EXTENSION_GROUP_NAME}" PUBLIC ${library_list})
  endif()

  get_property(include_folder_list GLOBAL PROPERTY OSQUERY_EXTENSION_GROUP_INCLUDE_FOLDERS)
  if(NOT "${include_folder_list}" STREQUAL "")
    target_include_directories("${OSQUERY_EXTENSION_GROUP_NAME}" PRIVATE
      ${include_folder_list}
    )
  endif()
endfunction()

function(add_osquery_extension_ex class_name extension_type extension_name ${ARGN})
  # Make sure the extension type is valid
  if(NOT "${extension_type}" STREQUAL "config" AND NOT "${extension_type}" STREQUAL "table")
    message(FATAL_ERROR "Invalid extension type specified")
  endif()

  # Update the initializer list; this will be added to the main.cpp file of the extension
  # group
  set_property(GLOBAL APPEND_STRING
    PROPERTY OSQUERY_EXTENSION_GROUP_INITIALIZERS
    "REGISTER_EXTERNAL(${class_name}, \"${extension_type}\", \"${extension_name}\");\n"
  )

  # Loop through each argument
  foreach(argument ${ARGN})
    if("${argument}" STREQUAL "SOURCES" OR "${argument}" STREQUAL "LIBRARIES" OR
      "${argument}" STREQUAL "INCLUDEDIRS" OR "${argument}" STREQUAL "MAININCLUDES")

      set(current_scope "${argument}")
      continue()
    endif()

    if("${current_scope}" STREQUAL "SOURCES")
      if(NOT IS_ABSOLUTE "${argument}")
        set(argument "${CMAKE_CURRENT_SOURCE_DIR}/${argument}")
      endif()

      list(APPEND source_file_list "${argument}")

    elseif("${current_scope}" STREQUAL "INCLUDEDIRS")
      if(NOT IS_ABSOLUTE "${argument}")
        set(argument "${CMAKE_CURRENT_SOURCE_DIR}/${argument}")
      endif()

      list(APPEND include_folder_list "${argument}")

    elseif("${current_scope}" STREQUAL "LIBRARIES")
      list(APPEND library_list "${argument}")
    elseif("${current_scope}" STREQUAL "MAININCLUDES")
      list(APPEND main_include_list "${argument}")
    else()
      message(FATAL_ERROR "Invalid scope")
    endif()
  endforeach()

  # Validate the arguments
  if("${source_file_list}" STREQUAL "")
    message(FATAL_ERROR "Source files are missing")
  endif()

  if("${main_include_list}" STREQUAL "")
    message(FATAL_ERROR "The main include list is missing")
  endif()

  # Update the global properties
  set_property(GLOBAL APPEND
    PROPERTY OSQUERY_EXTENSION_GROUP_SOURCES
    ${source_file_list}
  )

  set_property(GLOBAL APPEND
    PROPERTY OSQUERY_EXTENSION_GROUP_MAIN_INCLUDES
    ${main_include_list}
  )

  if(NOT "${library_list}" STREQUAL "")
    set_property(GLOBAL APPEND
      PROPERTY OSQUERY_EXTENSION_GROUP_LIBRARIES
      ${library_list}
    )
  endif()

  if(NOT "${include_folder_list}" STREQUAL "")
    set_property(GLOBAL APPEND
      PROPERTY OSQUERY_EXTENSION_GROUP_INCLUDE_FOLDERS
      ${include_folder_list}
    )
  endif()
endfunction()

# Helper to abstract OS/Compiler whole linking.
macro(TARGET_OSQUERY_LINK_WHOLE TARGET OSQUERY_LIB)
  if(WINDOWS)
      target_link_libraries(${TARGET} "${OS_WHOLELINK_PRE}$<TARGET_FILE_NAME:${OSQUERY_LIB}>")
      target_link_libraries(${TARGET} ${OSQUERY_LIB})
  else()
      target_link_libraries(${TARGET} "${OS_WHOLELINK_PRE}")
      target_link_libraries(${TARGET} ${OSQUERY_LIB})
      target_link_libraries(${TARGET} "${OS_WHOLELINK_POST}")
  endif()
endmacro(TARGET_OSQUERY_LINK_WHOLE)

macro(ADD_OSQUERY_EXTENSION TARGET)
  add_executable(${TARGET} ${ARGN})
  #TARGET_OSQUERY_LINK_WHOLE(${TARGET} libosquery)
  set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME "${TARGET}.ext")
endmacro(ADD_OSQUERY_EXTENSION)

###################################################


set(ROOT_TEST_TARGET "trailofbits_extensions_tests")
add_custom_target("${ROOT_TEST_TARGET}")

set(TOB_EXTENSIONS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")

set(ENV{OSQUERY_EXTENSION_GROUP_NAME} "trailofbits_osquery_extensions")
set(ENV{OSQUERY_EXTENSION_GROUP_VERSION} "1.2")

function(trailofbitsExtensionsMain)
  message(STATUS "================================")
  message(STATUS "Trail of Bits osquery extensions")
  message(STATUS "Version: $ENV{OSQUERY_EXTENSION_GROUP_VERSION}")
  message(STATUS "================================")

  ImportLibraries()
  ImportExtensions()

  message(STATUS "================================")
endfunction()

function(ImportLibraries)
  message("Importing libraries from '${CMAKE_CURRENT_SOURCE_DIR}/libraries/${library}'")

  file(GLOB library_list RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/libraries" "${CMAKE_CURRENT_SOURCE_DIR}/libraries/*")
  foreach(library ${library_list})
    set(full_library_path "${CMAKE_CURRENT_SOURCE_DIR}/libraries/${library}")
    if(NOT IS_DIRECTORY "${full_library_path}")
      continue()
    endif()

    IsFolderEnabled("libraries/${library}")
    if(NOT "${IsFolderEnabled_OUTPUT}")
      continue()
    endif()

    message(" > ${library}")
    add_subdirectory("${full_library_path}" "libraries/${library}")
  endforeach()
endfunction()

function(ImportDependency dependency_name)
  set(dependency_path "${TOB_EXTENSIONS_ROOT}/opt_dependencies/${dependency_name}")
  message("Importing dependency '${dependency_name}' from '${dependency_path}'")

  add_subdirectory("${dependency_path}" "opt_dependencies/${dependency_name}")
endfunction()

function(ImportExtensions)
  message("Importing extensions from '${CMAKE_CURRENT_SOURCE_DIR}'")

  if (DEFINED ENV{TRAILOFBITS_EXTENSIONS_TO_BUILD})
    set(extensions_to_build $ENV{TRAILOFBITS_EXTENSIONS_TO_BUILD})
    string(REPLACE "," ";" extensions_to_build "${extensions_to_build}")
  endif()

  file(GLOB extension_list RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/*")
  foreach(extension ${extension_list})
    if("${extension}" STREQUAL ".vscode")
      continue()
    endif()

    set(full_extension_path "${CMAKE_CURRENT_SOURCE_DIR}/${extension}")
    if(NOT IS_DIRECTORY "${full_extension_path}")
      continue()
    endif()

    if("${extension}" STREQUAL "libraries" OR "${extension}" STREQUAL ".git" OR "${extension}" STREQUAL "opt_dependencies")
      continue()
    endif()

    if (DEFINED extensions_to_build AND NOT "${extension}" IN_LIST extensions_to_build)
      continue()
    endif()

    IsFolderEnabled("${extension}")
    if(NOT "${IsFolderEnabled_OUTPUT}")
      continue()
    endif()

    message(" > ${extension}")
    add_subdirectory("${extension}" "extensions/${extension}")
  endforeach()
endfunction()

function(IsFolderEnabled relative_path)
  set(platforms_file_path "${CMAKE_CURRENT_SOURCE_DIR}/${relative_path}/.platforms")

  if(NOT EXISTS "${platforms_file_path}")
    message(" ! Missing '.platforms` file: ${relative_path}. Skipping...")

    set(IsFolderEnabled_OUTPUT false PARENT_SCOPE)
    return()
  endif()

  file(READ "${platforms_file_path}" supported_platforms)
  if(DEFINED PLATFORM_WINDOWS)
    string(FIND "${supported_platforms}" WINDOWS platform_match)
    if(${platform_match} EQUAL 0)
      set(IsFolderEnabled_OUTPUT true PARENT_SCOPE)
      return()
    endif()
  elseif(DEFINED PLATFORM_MACOS)
    string(FIND "${supported_platforms}" APPLE platform_match)
    if(${platform_match} EQUAL 0)
      set(IsFolderEnabled_OUTPUT true PARENT_SCOPE)
      return()
    endif()
  elseif(DEFINED PLATFORM_LINUX)
    string(FIND "${supported_platforms}" LINUX platform_match)
    if(${platform_match} EQUAL 0)
      set(IsFolderEnabled_OUTPUT true PARENT_SCOPE)
      return()
    endif()
  endif()

  #if(WINDOWS AND "${supported_platforms}" MATCHES "WINDOWS")
  #  set(IsFolderEnabled_OUTPUT true PARENT_SCOPE)
  #elseif(APPLE AND "${supported_platforms}" MATCHES "APPLE")
  #  set(IsFolderEnabled_OUTPUT true PARENT_SCOPE)
  #elseif(LINUX AND "${supported_platforms}" MATCHES "LINUX")
  #  set(IsFolderEnabled_OUTPUT true PARENT_SCOPE)
  #else()
  set(IsFolderEnabled_OUTPUT false PARENT_SCOPE)
  #endif()
endfunction()

function(AddTest test_name out_executable_target_name)
  set(target_name "tobExtTests_${test_name}")
  add_executable("${target_name}" EXCLUDE_FROM_ALL ${ARGN})

  message("   ${target_name}")

  # we have the guarantee that googletest is already present, thanks to osquery; link
  # to it so that we automatically import the include directories
  #if(NOT TARGET gtest)
  #  message(FATAL_ERROR "Tests will not find gtest if you have built using the 'SKIP_TESTS=1' setting!")
  # endif()

  target_link_libraries("${target_name}" PRIVATE gtest)

  if(UNIX)
    if(APPLE)
      target_compile_definitions("${target_name}" PRIVATE APPLE)
    else()
      set(command_prefix ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=/usr/local/osquery/lib)
      target_compile_definitions("${target_name}" PRIVATE LINUX)
    endif()
  else()
    target_compile_definitions("${target_name}" PRIVATE WINDOWS)
  endif()

  add_custom_target("${target_name}_runner"
    COMMAND ${command_prefix} $<TARGET_FILE:${target_name}>
    COMMENT "Running test: ${target_name}"
  )

  add_dependencies("${ROOT_TEST_TARGET}" "${target_name}_runner")

  # Return the executable target name to the caller
  set("${out_executable_target_name}" "${target_name}" PARENT_SCOPE)
endfunction()

trailofbitsExtensionsMain()

# If the user has generated extensions using the new generate_osquery_extension_group
# function, then this call will generate the bundle
generate_osquery_extension_group()
