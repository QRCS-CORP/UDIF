cmake_minimum_required(VERSION 3.15)

project(UDIF_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

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

# UDIF Static Library
file(GLOB_RECURSE UDIF_SOURCES "Source/UDIF/*.c")
file(GLOB_RECURSE UDIF_HEADERS "Source/UDIF/include/*.h")

add_library(udif STATIC ${UDIF_SOURCES} ${UDIF_HEADERS})
target_include_directories(udif PUBLIC "Source/UDIF")
target_link_libraries(udif PUBLIC qsc)

# UDIF URA
file(GLOB_RECURSE UDIF_URA_SOURCES "Source/URA/*.c")

add_executable(udif_ura ${UDIF_URA_SOURCES})
target_include_directories(udif_ura PRIVATE "Source/URA")
target_link_libraries(udif_ura PRIVATE udif)

# Warnings
foreach(target udif udif_ura)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()
