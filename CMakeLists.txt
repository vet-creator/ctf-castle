cmake_minimum_required(VERSION 3.15)
project(monolith C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Core cipher/VM sources shared by every target.
set(MONO_CORE
  src/sha256.c
  src/gf.c
  src/spn.c
  src/vm.c
)

# ---- build-time generator ---------------------------------------------------
# Emits generated/mono_data.h (encrypted program + target). Links the CLEAR
# program (bytecode_def.c); the shipped challenge does not.
add_executable(mono_gen tools/generator.c src/bytecode_def.c ${MONO_CORE})
target_include_directories(mono_gen PRIVATE src)

set(GEN_DIR ${CMAKE_BINARY_DIR}/generated)
set(GEN_HDR ${GEN_DIR}/mono_data.h)

# The generator runs at BUILD time, so a configure-time MONO_FLAG_INNER would
# otherwise be lost. Capture it here and forward it explicitly. (Setting the
# variable in the build step's environment also works -- both paths are honored.)
set(MONO_FLAG_INNER "$ENV{MONO_FLAG_INNER}" CACHE STRING
    "Flag inner text, exactly 32 characters. Empty = use generator default.")
mark_as_advanced(MONO_FLAG_INNER)

if(MONO_FLAG_INNER STREQUAL "")
  set(MONO_GEN_CMD mono_gen ${GEN_HDR})
else()
  set(MONO_GEN_CMD ${CMAKE_COMMAND} -E env
      "MONO_FLAG_INNER=${MONO_FLAG_INNER}" $<TARGET_FILE:mono_gen> ${GEN_HDR})
endif()

add_custom_command(
  OUTPUT  ${GEN_HDR}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${GEN_DIR}
  COMMAND ${MONO_GEN_CMD}
  DEPENDS mono_gen
  COMMENT "Generating embedded challenge data (mono_data.h)"
  VERBATIM
)
add_custom_target(mono_data DEPENDS ${GEN_HDR})
set_source_files_properties(${GEN_HDR} PROPERTIES GENERATED TRUE)

# ---- the challenge (this IS the CTF target) --------------------------------
add_executable(monolith src/main.c ${MONO_CORE})
add_dependencies(monolith mono_data)
target_include_directories(monolith PRIVATE src ${CMAKE_BINARY_DIR})

# ---- reference solver (designer tool; proves solvability) ------------------
add_executable(mono_solver tools/solver.c ${MONO_CORE})
add_dependencies(mono_solver mono_data)
target_include_directories(mono_solver PRIVATE src ${CMAKE_BINARY_DIR})

# ---- self-test --------------------------------------------------------------
add_executable(mono_selftest tests/selftest.c src/bytecode_def.c ${MONO_CORE})
add_dependencies(mono_selftest mono_data)
target_include_directories(mono_selftest PRIVATE src ${CMAKE_BINARY_DIR})

# MSVC: silence CRT "deprecation" of fopen/sprintf (these uses are fine).
if(MSVC)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# ---- tests ------------------------------------------------------------------
enable_testing()
add_test(NAME selftest COMMAND mono_selftest)
add_test(NAME integration
  COMMAND ${CMAKE_COMMAND}
          -DSOLVER=$<TARGET_FILE:mono_solver>
          -DAPP=$<TARGET_FILE:monolith>
          -P ${CMAKE_SOURCE_DIR}/tests/integration.cmake)
