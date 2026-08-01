# KaguraCompilerSetup.cmake — host compiler flags and the build cache.
#
# Split out of the root CMakeLists so that file reads as a table of contents
# rather than a hundred lines of MSVC warning suppressions.

include_guard(GLOBAL)

# ---- Windows compiler flags --------------------------------------------------

function(kagura_configure_compiler)
  if(MSVC)
    # /utf-8          : source and execution charset both UTF-8
    # /W3             : warning level 3 (roughly clang -Wall)
    # /WX-            : warnings are not errors (LLVM headers trigger several)
    # /EHsc           : standard C++ exception handling, required by LLVM
    # /Zc:__cplusplus : make __cplusplus report the real standard
    # /wd4624 /wd4244 : common LLVM-generated warnings on MSVC
    add_compile_options(/utf-8 /W3 /WX- /EHsc /Zc:__cplusplus /wd4624 /wd4244)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)
  elseif(WIN32)
    # Clang-CL or a MinGW cross-compile targeting Windows.
    add_compile_options(-Wall -Wno-unused-parameter)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)
  endif()
endfunction()

# ---- Compiler cache ----------------------------------------------------------

function(kagura_configure_build_cache)
  if(NOT KAGURA_USE_CACHE)
    return()
  endif()
  # Prefer sccache; it can share a cache across machines.
  find_program(SCCACHE_PROGRAM sccache)
  find_program(CCACHE_PROGRAM  ccache)
  if(SCCACHE_PROGRAM)
    set(_launcher "${SCCACHE_PROGRAM}")
    message(STATUS "[kagura] Build cache: sccache (${SCCACHE_PROGRAM})")
  elseif(CCACHE_PROGRAM)
    set(_launcher "${CCACHE_PROGRAM}")
    message(STATUS "[kagura] Build cache: ccache (${CCACHE_PROGRAM})")
  else()
    message(STATUS "[kagura] Build cache: none found (install ccache or sccache)")
    return()
  endif()
  set(CMAKE_C_COMPILER_LAUNCHER   "${_launcher}" PARENT_SCOPE)
  set(CMAKE_CXX_COMPILER_LAUNCHER "${_launcher}" PARENT_SCOPE)
endfunction()
