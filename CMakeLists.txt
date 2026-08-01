cmake_minimum_required(VERSION 3.20)
project(kagura VERSION 0.2.1 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# A bare `cmake -B build` used to produce a no-optimisation, no-NDEBUG build
# that matched nothing anyone actually ships. Default to RelWithDebInfo, which
# keeps assertions compiled out like the CI and release builds while staying
# debuggable. Pass -DCMAKE_BUILD_TYPE=Debug to get assertions.
get_property(_kagura_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT _kagura_multi_config AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
      "Build type: Debug, Release, RelWithDebInfo or MinSizeRel" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
               STRINGS Debug Release RelWithDebInfo MinSizeRel)
  message(STATUS "[kagura] CMAKE_BUILD_TYPE not set — defaulting to RelWithDebInfo")
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(KaguraOptions)          # every user-facing KAGURA_* option
include(KaguraCompilerSetup)    # MSVC flags, ccache/sccache
include(KaguraWindowsLLVMFixup) # prune stale absolute paths from LLVM exports
include(KaguraInstall)          # install()/EXPORT rules

kagura_configure_compiler()
kagura_configure_build_cache()

# ---- LLVM --------------------------------------------------------------------

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

# Pull in LLVM's CMake helpers (provides add_llvm_pass_plugin etc.)
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

kagura_prune_stale_llvm_link_paths()

# ---- Kagura headers ----------------------------------------------------------
#
# PROJECT_SOURCE_DIR, not CMAKE_SOURCE_DIR: the latter points at the top-level
# project, which is not this one when kagura is pulled in via
# add_subdirectory() — the embedding that integration/cmake/kagura-toolchain.cmake
# and samples/basic/ both encourage.
include_directories(${PROJECT_SOURCE_DIR}/include)

if(KAGURA_PCH)
  set(CMAKE_DISABLE_PRECOMPILE_HEADERS OFF)
endif()

# ---- Legacy pass manager compatibility ---------------------------------------
# LegacyPlugin.cpp registers the passes with LLVM 14-16's legacy PM via
# PassManagerBuilder extension points and RegisterPass<>. Newer LLVM has
# removed those APIs.
if(KAGURA_LEGACY_PM)
  if(LLVM_VERSION_MAJOR GREATER 16)
    message(WARNING "[kagura] KAGURA_LEGACY_PM=ON but LLVM ${LLVM_VERSION_MAJOR} "
                    "has removed legacy PM APIs — disabling.")
    set(KAGURA_LEGACY_PM OFF)
  else()
    message(STATUS "[kagura] Legacy PM shims enabled (LLVM ${LLVM_VERSION_MAJOR})")
  endif()
endif()

# ---- Plugin linkage mode -----------------------------------------------------
# LLVM cannot build loadable pass modules everywhere — the MSVC-targeted
# Windows tarball ships LLVM_ENABLE_PLUGINS=OFF, so `-fpass-plugin` and
# `opt --load-pass-plugin` are both unavailable there. On those platforms the
# passes are built as a static library and linked directly into kagura-opt,
# which calls getKaguraPluginInfo() rather than dlopen()ing a module.
#
# Derived, not an option: named without the KAGURA_ user-option prefix would be
# clearer still, but it is read from lib/, tests/ and tools/ and renaming it is
# left for a separate change.
if(LLVM_ENABLE_PLUGINS AND NOT KAGURA_FORCE_STATIC_PLUGIN)
  set(KAGURA_PLUGIN_STATIC OFF)
  message(STATUS "[kagura] Plugin linkage: loadable module (-fpass-plugin)")
else()
  set(KAGURA_PLUGIN_STATIC ON)
  message(STATUS "[kagura] Plugin linkage: static library (link into kagura-opt)")
endif()

# ---- Targets -----------------------------------------------------------------

# Passes (loaded as a plugin via -fpass-plugin)
add_subdirectory(lib)

# Runtime library linked into the protected application
add_subdirectory(runtime)

# Bitcode tools (kagura-opt). Configured before tests so the link smoke tests
# can depend on the targets it defines.
if(KAGURA_BITCODE_TOOLS)
  add_subdirectory(tools)
endif()

if(KAGURA_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

kagura_add_install_rules()
