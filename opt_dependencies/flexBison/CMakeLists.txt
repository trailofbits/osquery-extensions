cmake_minimum_required(VERSION 3.12)

function(importFlexBison)
  foreach(lib FLEX BISON)
    find_package("${lib}" REQUIRED)
  endforeach()
endfunction()

importFlexBison()
