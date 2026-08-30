# minicontainer test suite.
#
# Like the root CMakeLists.txt, this file uses CONFIGURE_DEPENDS globs so new
# test files picked up by any of the five parallel agents are compiled
# automatically - this file should never need editing when a *_test.cpp
# appears.
#
# Two binaries:
#   mc_unit_tests        - tests/unit/*.cpp. No root, no namespaces, no
#                           mounting. Runs anywhere, including plain CI.
#   mc_integration_tests - tests/integration/*.cpp plus the per-subsystem
#                           dirs (namespace/cgroup/filesystem/network/
#                           security). These need root and a real Linux
#                           kernel; they are labelled "root" so
#                           `ctest -LE root` skips them.

find_package(GTest QUIET)
if(NOT GTest_FOUND)
  message(STATUS "GTest not found via find_package(); falling back to FetchContent")
  include(FetchContent)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
  )
  FetchContent_MakeAvailable(googletest)
  add_library(GTest::gtest ALIAS gtest)
  add_library(GTest::gtest_main ALIAS gtest_main)
  add_library(GTest::gmock ALIAS gmock)
  add_library(GTest::gmock_main ALIAS gmock_main)
endif()

include(GoogleTest)

# Shared test helpers (fixtures, fakes) that both binaries may use. Optional:
# tests/support/ may be empty for a long time.
file(GLOB_RECURSE MC_TEST_SUPPORT_SOURCES CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/support/*.cpp")

# ---------------------------------------------------------------------------
# mc_unit_tests
# ---------------------------------------------------------------------------
file(GLOB_RECURSE MC_UNIT_TEST_SOURCES CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/unit/*.cpp")

if(MC_UNIT_TEST_SOURCES)
  add_executable(mc_unit_tests ${MC_UNIT_TEST_SOURCES} ${MC_TEST_SUPPORT_SOURCES})
  target_include_directories(mc_unit_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/support"
    "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(mc_unit_tests PRIVATE
    mc_core GTest::gtest GTest::gtest_main GTest::gmock)
  mc_apply_warnings(mc_unit_tests)
  mc_apply_sanitizers(mc_unit_tests)
  gtest_discover_tests(mc_unit_tests PROPERTIES LABELS "unit")
else()
  message(STATUS "tests/unit is empty; mc_unit_tests target not created yet")
endif()

# ---------------------------------------------------------------------------
# mc_integration_tests - needs root/namespaces/mounts. LABELS root so
# `ctest -LE root` (used in unprivileged CI) skips it.
# ---------------------------------------------------------------------------
set(MC_INTEGRATION_DIRS
    integration
    namespace
    cgroup
    filesystem
    network
    security)

set(MC_INTEGRATION_TEST_SOURCES "")
foreach(_dir ${MC_INTEGRATION_DIRS})
  file(GLOB_RECURSE _dir_sources CONFIGURE_DEPENDS
       "${CMAKE_CURRENT_SOURCE_DIR}/${_dir}/*.cpp")
  list(APPEND MC_INTEGRATION_TEST_SOURCES ${_dir_sources})
endforeach()

if(MC_INTEGRATION_TEST_SOURCES)
  add_executable(mc_integration_tests ${MC_INTEGRATION_TEST_SOURCES} ${MC_TEST_SUPPORT_SOURCES})
  target_include_directories(mc_integration_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/support"
    "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(mc_integration_tests PRIVATE
    mc_core GTest::gtest GTest::gtest_main GTest::gmock)
  mc_apply_warnings(mc_integration_tests)
  mc_apply_sanitizers(mc_integration_tests)
  gtest_discover_tests(mc_integration_tests PROPERTIES LABELS "root")
else()
  message(STATUS "no integration test sources yet; mc_integration_tests target not created yet")
endif()
