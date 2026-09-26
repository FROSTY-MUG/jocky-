# ==============================================================================
# JOCKY Windows Agent (C++) - CMake build definition
# Purpose: Builds the native Windows JOCKY agent executable.
# Blueprint: Section 3 Agent Runtime (STEP 2B scaffold).
# Requires: CMake 3.20+, a C++20 compiler (MSVC or clang-cl).
# ==============================================================================
cmake_minimum_required(VERSION 3.20)

project(jocky-agent-win
        VERSION 0.1.0
        DESCRIPTION "JOCKY Windows agent (scaffold)"
        LANGUAGES CXX)

# C++20 as mandated by the blueprint (T11).
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_executable(jocky-agent-win src/main.cpp)

# Emit the target version into the binary so `--version` needs no hardcoding.
target_compile_definitions(jocky-agent-win PRIVATE
  JOCKY_AGENT_VERSION="${PROJECT_VERSION}"
  JOCKY_AGENT_NAME="${PROJECT_NAME}")

if(MSVC)
  target_compile_options(jocky-agent-win PRIVATE /W4 /permissive-)
else()
  target_compile_options(jocky-agent-win PRIVATE -Wall -Wextra -Wpedantic)
endif()
