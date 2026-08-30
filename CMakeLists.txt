cmake_minimum_required(VERSION 3.20)

project(minicontainer VERSION 0.1.0 LANGUAGES CXX)

# ---------------------------------------------------------------------------
# CRITICAL DESIGN CONSTRAINT
# ---------------------------------------------------------------------------
# Five agents work on this codebase in parallel. This file must NEVER need
# editing when a module's .cpp files appear. Every source list below is a
# CONFIGURE_DEPENDS glob: re-running cmake (which Ninja does automatically
# whenever a CMakeLists.txt-adjacent file's mtime changes) re-scans the
# filesystem and new files are compiled without anyone touching this file.
# ---------------------------------------------------------------------------

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(MC_ENABLE_SECCOMP "Build with libseccomp support" ON)
option(MC_ENABLE_ASAN "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(MC_ENABLE_UBSAN "Build with UndefinedBehaviorSanitizer" OFF)
option(MC_BUILD_TESTS "Build the test suite" ON)
option(MC_WERROR "Treat warnings as errors" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(GNUInstallDirs)
include(McWarnings)
include(McSanitizers)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCAP REQUIRED IMPORTED_TARGET libcap)

set(MC_SECCOMP_FOUND FALSE)
if(MC_ENABLE_SECCOMP)
  pkg_check_modules(LIBSECCOMP IMPORTED_TARGET libseccomp)
  if(LIBSECCOMP_FOUND)
    set(MC_SECCOMP_FOUND TRUE)
  else()
    message(WARNING "MC_ENABLE_SECCOMP is ON but libseccomp was not found via pkg-config; building without seccomp support")
  endif()
endif()

# ---------------------------------------------------------------------------
# Debug / Release flags. -g3 keeps macro info for gdb; sanitizers never touch
# mc_child (see mc_apply_sanitizers below, which is simply not called on it).
# ---------------------------------------------------------------------------
add_compile_options(
  "$<$<CONFIG:Debug>:-g3;-O0>"
  "$<$<CONFIG:Release>:-O2>"
)

# ---------------------------------------------------------------------------
# mc_child: code that runs after clone(), before execve(). -fno-exceptions
# -fno-rtti because throwing or the allocator's exception machinery here can
# wedge the process forever (see errors.h's header comment on ChildStatus).
# May legitimately have zero sources for a while; handle that gracefully.
# ---------------------------------------------------------------------------
file(GLOB_RECURSE MC_CHILD_SOURCES CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/src/child/*.cpp")

if(MC_CHILD_SOURCES)
  add_library(mc_child STATIC ${MC_CHILD_SOURCES})
else()
  set(MC_CHILD_PLACEHOLDER "${CMAKE_CURRENT_BINARY_DIR}/generated/mc_child_placeholder.cpp")
  file(WRITE "${MC_CHILD_PLACEHOLDER}"
       "// Auto-generated placeholder: src/child/ has no sources yet.\n")
  add_library(mc_child STATIC "${MC_CHILD_PLACEHOLDER}")
endif()

target_include_directories(mc_child PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")
target_compile_options(mc_child PRIVATE -fno-exceptions -fno-rtti)
mc_apply_warnings(mc_child)

# ---------------------------------------------------------------------------
# mc_core: everything else under src/, except src/child/* (its own target,
# different flags) and src/cli/main.cpp (belongs to the executable, not a
# library one could link twice).
# ---------------------------------------------------------------------------
file(GLOB_RECURSE MC_CORE_SOURCES_ALL CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

set(MC_CORE_SOURCES "")
foreach(_src ${MC_CORE_SOURCES_ALL})
  if(_src MATCHES "/src/child/" OR _src STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/main.cpp")
    continue()
  endif()
  list(APPEND MC_CORE_SOURCES "${_src}")
endforeach()

if(MC_CORE_SOURCES)
  add_library(mc_core STATIC ${MC_CORE_SOURCES})
else()
  set(MC_CORE_PLACEHOLDER "${CMAKE_CURRENT_BINARY_DIR}/generated/mc_core_placeholder.cpp")
  file(WRITE "${MC_CORE_PLACEHOLDER}"
       "// Auto-generated placeholder: src/ has no core sources yet.\n")
  add_library(mc_core STATIC "${MC_CORE_PLACEHOLDER}")
endif()

target_include_directories(mc_core PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")
target_link_libraries(mc_core PUBLIC mc_child PkgConfig::LIBCAP)

if(MC_SECCOMP_FOUND)
  target_link_libraries(mc_core PUBLIC PkgConfig::LIBSECCOMP)
  target_compile_definitions(mc_core PUBLIC MC_ENABLE_SECCOMP=1)
else()
  target_compile_definitions(mc_core PUBLIC MC_ENABLE_SECCOMP=0)
endif()

# The version string the `version` subcommand prints. Sourced from project()
# above so there is exactly one place to bump it. PUBLIC because the tests link
# mc_core and assert on what `version` reports.
target_compile_definitions(mc_core PUBLIC
  MC_VERSION_STRING="${PROJECT_VERSION}")

mc_apply_warnings(mc_core)
mc_apply_sanitizers(mc_core)

# ---------------------------------------------------------------------------
# minicontainer: the CLI executable.
# ---------------------------------------------------------------------------
set(MC_MAIN_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/main.cpp")
if(EXISTS "${MC_MAIN_SOURCE}")
  add_executable(minicontainer "${MC_MAIN_SOURCE}")
else()
  set(MC_MAIN_PLACEHOLDER "${CMAKE_CURRENT_BINARY_DIR}/generated/mc_main_placeholder.cpp")
  file(WRITE "${MC_MAIN_PLACEHOLDER}"
       "// Auto-generated placeholder: src/cli/main.cpp does not exist yet.\n"
       "int main() { return 0; }\n")
  add_executable(minicontainer "${MC_MAIN_PLACEHOLDER}")
endif()

target_link_libraries(minicontainer PRIVATE mc_core)
mc_apply_warnings(minicontainer)
mc_apply_sanitizers(minicontainer)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(MC_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

message(STATUS "minicontainer configuration summary:")
message(STATUS "  CMAKE_BUILD_TYPE     = ${CMAKE_BUILD_TYPE}")
message(STATUS "  MC_ENABLE_SECCOMP    = ${MC_ENABLE_SECCOMP} (found: ${MC_SECCOMP_FOUND})")
message(STATUS "  MC_ENABLE_ASAN       = ${MC_ENABLE_ASAN}")
message(STATUS "  MC_ENABLE_UBSAN      = ${MC_ENABLE_UBSAN}")
message(STATUS "  MC_BUILD_TESTS       = ${MC_BUILD_TESTS}")
message(STATUS "  MC_WERROR            = ${MC_WERROR}")
message(STATUS "  version              = ${PROJECT_VERSION}")
message(STATUS "  mc_child sources     = ${MC_CHILD_SOURCES}")
message(STATUS "  mc_core sources      = ${MC_CORE_SOURCES}")
