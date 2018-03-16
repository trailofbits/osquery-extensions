cmake_minimum_required(VERSION 3.10.0)
project(hostsfile)

function(main)
  set(PROJECT_SOURCEFILES
    src/hostsfile.h
    src/hostsfile.cpp
  )

  set(PROJECT_PUBLICINCLUDEFOLDER "${CMAKE_CURRENT_SOURCE_DIR}/include")

  list(APPEND PROJECT_SOURCEFILES
    "${PROJECT_PUBLICINCLUDEFOLDER}/trailofbits/ihostsfile.h"
  )

  add_library("${PROJECT_NAME}" STATIC ${PROJECT_SOURCEFILES})
  target_include_directories("${PROJECT_NAME}" PUBLIC "${PROJECT_PUBLICINCLUDEFOLDER}")
  target_link_libraries("${PROJECT_NAME}" PUBLIC extutils)
endfunction()

main()
