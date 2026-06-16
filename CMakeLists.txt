cmake_minimum_required(VERSION 3.15)

project(UDIF_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build-type default for single-config generators
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Output dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Download and build QSC
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# Download and build MCEL
include(FetchContent)
FetchContent_Declare(
  MCEL
  GIT_REPOSITORY https://github.com/QRCS-CORP/MCEL.git
  GIT_TAG main
)
FetchContent_MakeAvailable(MCEL)

# Download and build QSTP
include(FetchContent)
FetchContent_Declare(
  QSTP
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSTP.git
  GIT_TAG main
)
FetchContent_MakeAvailable(QSTP)

# UDIF Static Library
file(GLOB_RECURSE UDIF_SOURCES "Source/UDIF/*.c")
file(GLOB_RECURSE UDIF_HEADERS "Source/UDIF/*.h")

add_library(udif STATIC ${UDIF_SOURCES} ${UDIF_HEADERS})
target_include_directories(udif PUBLIC "Source/UDIF")
target_link_libraries(udif PUBLIC qsc)
target_link_libraries(udif PUBLIC mcel)
target_link_libraries(udif PUBLIC qstp)

# Warnings
foreach(target udif)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()
