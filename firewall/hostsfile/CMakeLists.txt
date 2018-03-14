cmake_minimum_required(VERSION 3.10.0)
project(hostsfile)

function(main)
  if(DEFINED APPLE)
    set(PROJECT_SOURCEFILES
      macos/hostsfile.h
      macos/hostsfile.cpp
    )

  elseif(DEFINED UNIX)
    set(PROJECT_SOURCEFILES
      linux/hostsfile.h
      linux/hostsfile.cpp
    )

  elseif(DEFINED WIN32)
    set(PROJECT_SOURCEFILES
      windows/hostsfile.h
      windows/hostsfile.cpp
    )

  else()
    message(SEND_ERROR "Unsupported operating system")
  endif()

  set(PROJECT_PUBLICINCLUDEFOLDER "${CMAKE_CURRENT_SOURCE_DIR}/include")

  list(APPEND PROJECT_SOURCEFILES
    "${PROJECT_PUBLICINCLUDEFOLDER}/trailofbits/ihostsfile.h"
  )

  add_library("${PROJECT_NAME}" STATIC ${PROJECT_SOURCEFILES})
  target_include_directories("${PROJECT_NAME}" PUBLIC "${PROJECT_PUBLICINCLUDEFOLDER}")
  target_link_libraries("${PROJECT_NAME}" PUBLIC extutils)
endfunction()

main()
