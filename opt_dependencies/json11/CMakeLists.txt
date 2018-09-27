cmake_minimum_required(VERSION 3.12)
project(json11)

function(json11Main)
  set(source_files
    src/json11.hpp
    src/json11.cpp
  )

  add_library("${PROJECT_NAME}" STATIC ${source_files})
  target_include_directories("${PROJECT_NAME}" PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
endfunction()

json11Main()

