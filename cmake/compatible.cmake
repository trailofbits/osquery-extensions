

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  set(PLATFORM_POSIX 1)
  set(PLATFORM_LINUX 1)
elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
  set(PLATFORM_POSIX 1)
  set(PLATFORM_MACOS 1)
elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
  set(PLATFORM_WINDOWS 1)
else()
  message(FATAL_ERROR "Unrecognized platform")
endif()

macro(addOsqueryExtension TARGET)
  add_osquery_extension(${TARGET} ${ARGN})
endmacro(addOsqueryExtension)

macro(addOsqueryExtensionEx)
  add_osquery_extension_ex(${ARGN})
endmacro(addOsqueryExtensionEx)

macro(generateOsqueryExtensionGroup)
  generate_osquery_extension_group()
endmacro(generateOsqueryExtensionGroup)