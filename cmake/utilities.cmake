###################################################
##       utilities.cmake
###################################################

function(get_version_number versionstring version)
  string(REPLACE "." ";" version_list ${versionstring} )
  list(GET version_list 0 major)
  list(GET version_list 1 minor)
  list(GET version_list 2 patch)
  string(REPLACE "-" ";" patch_list ${patch} )
  list(GET patch_list 0 patch)
  math(EXPR value "${major} * 1000 + ${minor} * 100 + ${patch}")
  set(version ${value} PARENT_SCOPE)
endfunction()

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

  if(DEFINED PLATFORM_POSIX)
    set(extension_cxx_flags ${cxx_settings} -DBOOST_ASIO_DISABLE_STD_STRING_VIEW)
  else()
    set(extension_cxx_flags /W4)
  endif()

  # Generate the extension target
  add_executable("${OSQUERY_EXTENSION_GROUP_NAME}"
    "${CMAKE_CURRENT_BINARY_DIR}/osquery_extension_group_main.cpp"
    ${extension_source_files}
  )

  set_property(TARGET "${OSQUERY_EXTENSION_GROUP_NAME}" PROPERTY INCLUDE_DIRECTORIES "")
  target_compile_options("${OSQUERY_EXTENSION_GROUP_NAME}" PRIVATE ${extension_cxx_flags})

  get_version_number(${OSQUERY_VERSION_INTERNAL} version)
  target_compile_options("${OSQUERY_EXTENSION_GROUP_NAME}" PRIVATE -DOSQUERY_VERSION_NUMBER=${version})

  target_link_libraries("${OSQUERY_EXTENSION_GROUP_NAME}" PUBLIC
  	osquery_sdk_pluginsdk
  	osquery_extensions_implthrift
	thirdparty_boost
  )
  
  if(DEFINED PLATFORM_LINUX)
    target_link_libraries("${OSQUERY_EXTENSION_GROUP_NAME}" PUBLIC
	  thirdparty_libiptc
  	)
  endif()

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
  if(PLATFORM_WINDOWS)
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
  set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME "${TARGET}.ext")
endmacro(ADD_OSQUERY_EXTENSION)