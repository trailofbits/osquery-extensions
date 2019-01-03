cmake_minimum_required(VERSION 3.12)
project(EndianPortable)

function(EndianPortableMain)
  set(public_headers_folder "${PCAPPLUSPLUS_ROOT}/3rdParty/EndianPortable/include")

  add_library("${PROJECT_NAME}" INTERFACE)
  target_include_directories("${PROJECT_NAME}" SYSTEM INTERFACE ${public_headers_folder})
endfunction()

EndianPortableMain()
