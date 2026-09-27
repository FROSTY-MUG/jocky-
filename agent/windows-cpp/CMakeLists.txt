# ==============================================================================
# JOCKY Windows Agent (C++) - CMake build definition
# Purpose: Builds the native Windows JOCKY agent executable.
# Blueprint: Section 3 Agent Runtime (STEP 3A).
# Requires: CMake 3.20+, a C++20 compiler (MSVC or clang-cl).
# ==============================================================================
cmake_minimum_required(VERSION 3.20)

project(jocky-agent-win
        VERSION 0.1.0
        DESCRIPTION "JOCKY Windows agent"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

include(FetchContent)
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(json)

set(RUST_DIR "${CMAKE_SOURCE_DIR}/../../target/release")
if(MSVC)
    set(RUST_LIB "${RUST_DIR}/jocky_common.dll.lib")
    set(RUST_DLL "${RUST_DIR}/jocky_common.dll")
else()
    set(RUST_LIB "${RUST_DIR}/libjocky_common.so")
    set(RUST_DLL "${RUST_DIR}/libjocky_common.so")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/../../agent/common/include)

set(AGENT_LIBS ${RUST_LIB} nlohmann_json::nlohmann_json ntdll psapi iphlpapi bcrypt crypt32 ws2_32 advapi32 tdh)

set(SRC_FILES
    src/agent.cpp
    src/consent.cpp
    src/module_loader.cpp
    src/output.cpp
    src/collectors/process.cpp
    src/collectors/network.cpp
    src/collectors/driver.cpp
    src/detect/byovd.cpp
    src/detect/inject.cpp
)

add_compile_definitions(_CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX)

add_executable(jocky-agent-win src/main.cpp ${SRC_FILES})

target_compile_definitions(jocky-agent-win PRIVATE
  JOCKY_AGENT_VERSION="${PROJECT_VERSION}"
  JOCKY_AGENT_NAME="${PROJECT_NAME}")

if(MSVC)
  target_compile_options(jocky-agent-win PRIVATE /W4 /WX /permissive-)
else()
  target_compile_options(jocky-agent-win PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

target_link_libraries(jocky-agent-win PRIVATE ${AGENT_LIBS})

add_custom_command(TARGET jocky-agent-win POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${RUST_DLL}"
    $<TARGET_FILE_DIR:jocky-agent-win>
)

enable_testing()

macro(add_agent_test TEST_NAME FILE_NAME)
    add_executable(${TEST_NAME} ${FILE_NAME} ${SRC_FILES})
    target_compile_definitions(${TEST_NAME} PRIVATE
      JOCKY_AGENT_VERSION="${PROJECT_VERSION}"
      JOCKY_AGENT_NAME="${PROJECT_NAME}")
    target_link_libraries(${TEST_NAME} PRIVATE ${AGENT_LIBS})
    if(MSVC)
        target_compile_options(${TEST_NAME} PRIVATE /W4 /WX /permissive-)
    endif()
    add_custom_command(TARGET ${TEST_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${RUST_DLL}"
        $<TARGET_FILE_DIR:${TEST_NAME}>
    )
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endmacro()

add_agent_test(test_consent tests/test_consent.cpp)
add_agent_test(test_module_loader tests/test_module_loader.cpp)
add_agent_test(test_collectors tests/test_collectors.cpp)
add_agent_test(test_byovd tests/test_byovd.cpp)
add_agent_test(test_inject tests/test_inject.cpp)

add_custom_target(run_all_tests
    COMMAND ${CMAKE_CTEST_COMMAND} -C Release --output-on-failure
    DEPENDS test_consent test_module_loader test_collectors test_byovd test_inject
)
