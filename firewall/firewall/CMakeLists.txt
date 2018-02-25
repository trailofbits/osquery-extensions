cmake_minimum_required(VERSION 3.10.0)
project(firewall)

function(main)
  if(DEFINED APPLE)
    set(PROJECT_SOURCEFILES
      macos/firewall.h
      macos/firewall.cpp
    )

  elseif(DEFINED UNIX)
    set(PROJECT_SOURCEFILES
      linux/firewall.h
      linux/firewall.cpp
    )

  elseif(DEFINED WIN32)
    set(PROJECT_SOURCEFILES
      windows/firewall.h
      windows/firewall.cpp
    )

  else()
    message(SEND_ERROR "Unsupported operating system")
  endif()

  set(PROJECT_PUBLICINCLUDEFOLDER "${CMAKE_CURRENT_SOURCE_DIR}/include")

  list(APPEND PROJECT_SOURCEFILES
    "${PROJECT_PUBLICINCLUDEFOLDER}/trailofbits/istatus.h"
    "${PROJECT_PUBLICINCLUDEFOLDER}/trailofbits/ifirewall.h"
  )

  add_library("${PROJECT_NAME}" STATIC ${PROJECT_SOURCEFILES})
  target_include_directories("${PROJECT_NAME}" PUBLIC "${PROJECT_PUBLICINCLUDEFOLDER}")
endfunction()

main()
