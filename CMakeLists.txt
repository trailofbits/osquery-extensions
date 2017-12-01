cmake_minimum_required(VERSION 3.9.1)
project(efigy)

set(CMAKE_VERBOSE_MAKEFILE TRUE)

function (main)
  set(PROJECT_SOURCEFILES
    src/utils.h
    src/utils.mm

    src/efigy.h
    src/efigy.cpp

    src/extension.h
    src/extension.cpp

    src/main.cpp
  )

  ADD_OSQUERY_EXTENSION("${PROJECT_NAME}" ${PROJECT_SOURCEFILES})
  target_link_libraries("${PROJECT_NAME}" "-framework CoreFoundation" "-framework IOKit")

  find_package(curl REQUIRED)
  target_link_libraries("${PROJECT_NAME}" ${CURL_LIBRARIES})
  target_include_directories("${PROJECT_NAME}" PRIVATE ${CURL_INCLUDE_DIR})
endfunction ()

main()

