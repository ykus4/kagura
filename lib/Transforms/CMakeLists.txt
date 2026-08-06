llvm_map_components_to_libnames(LLVM_LIBS
  Core
  Support
  Analysis
  TransformUtils
  Passes
)

# ---- Sources -----------------------------------------------------------------
#
# One directory per pass category. Each directory is both a source list entry
# and, under KAGURA_UNITY_BUILD, one unity translation unit, so adding a pass
# means adding a file — this list does not change.
#
# It used to be written out by hand and then *repeated* in the unity-build
# section below, and the two copies had already diverged: Data/CSEBreak.cpp,
# Data/StringSplit.cpp, Data/EncryptedLookupTable.cpp and everything under
# Platform/ and Infrastructure/ were in the source list but in no group.
set(KAGURA_PASS_DIRS
  ABI              # C++ ABI: RTTI names, vtable integrity
  AntiAnalysis     # anti-debug, anti-tamper, decoys, call indirection
  CFG              # control-flow structure
  Data             # constants, strings, globals, in-memory values
  Infrastructure   # policy, metrics and reporting; not obfuscation itself
  Platform         # ObjC / JNI language-runtime specifics
  VM               # function virtualization
)

# Non-pass translation units: option definitions, plugin registration and the
# helpers every pass shares. Compiled individually — merging them into a unity
# TU buys nothing because nothing else lives in their directory.
set(KAGURA_SOURCES
  Options.cpp
  Plugin.cpp
  Utils.cpp
)

foreach(_dir IN LISTS KAGURA_PASS_DIRS)
  file(GLOB KAGURA_GROUP_${_dir} CONFIGURE_DEPENDS
       "${CMAKE_CURRENT_SOURCE_DIR}/${_dir}/*.cpp")
  if(NOT KAGURA_GROUP_${_dir})
    message(FATAL_ERROR "[kagura] lib/Transforms/${_dir}/ has no sources — "
                        "remove it from KAGURA_PASS_DIRS or add the pass.")
  endif()
  list(APPEND KAGURA_SOURCES ${KAGURA_GROUP_${_dir}})
endforeach()

if(NOT KAGURA_PLUGIN_STATIC)
  # Normal path: build as a loadable MODULE (macOS .dylib / Linux .so)
  add_llvm_pass_plugin(KaguraObfuscator
    PARTIAL_SOURCES_INTENDED
    ${KAGURA_SOURCES}
    DEPENDS intrinsics_gen
  )
else()
  # Fallback for platforms where loadable modules are unsupported (e.g. MSVC).
  # add_llvm_pass_plugin() would create a non-compilable UTILITY target and
  # then abort on subsequent target_* calls.  Build as a static library so
  # the plugin can be linked directly into a driver tool instead — see
  # tools/kagura-opt.cpp, which calls getKaguraPluginInfo() directly.
  add_library(KaguraObfuscator STATIC ${KAGURA_SOURCES})
  llvm_update_compile_flags(KaguraObfuscator)
  # Deliberately *not* linking ${LLVM_LIBS} here.  A static archive does not
  # resolve LLVM symbols itself — the final executable does — and depending on
  # the imported LLVM targets drags their INTERFACE include dirs in as
  # -isystem, which on macOS puts the SDK C headers ahead of libc++ and breaks
  # <cstddef>.  The consumer links the components instead; see
  # tools/CMakeLists.txt (KAGURA_OPT_LLVM_LIBS).
endif()

target_include_directories(KaguraObfuscator PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# ---- Incremental build: precompiled header ----------------------------------
# PCH is not supported on static libraries in all CMake versions; skip on
# the fallback static build to keep the Windows build simple.
if(KAGURA_PCH AND NOT KAGURA_PLUGIN_STATIC)
  target_precompile_headers(KaguraObfuscator PRIVATE
    <llvm/IR/Function.h>
    <llvm/IR/Module.h>
    <llvm/IR/IRBuilder.h>
    <llvm/IR/Instructions.h>
    <llvm/IR/Constants.h>
    <llvm/IR/PassManager.h>
    <llvm/Support/raw_ostream.h>
  )
endif()

# ---- Incremental build: unity build ----------------------------------------
#
# UNITY_BUILD_MODE must be GROUP for the UNITY_GROUP source property to mean
# anything. Without it CMake ignores the groups and batches every source by
# UNITY_BUILD_BATCH_SIZE instead, which is what this project was doing: the
# groups were set but never honoured, so unity TUs were assembled in whatever
# order the source list happened to be in, mixing categories.
#
# Sources with no UNITY_GROUP (Options.cpp and friends) are compiled on their
# own under GROUP mode, which is what we want for them.
if(KAGURA_UNITY_BUILD)
  set_target_properties(KaguraObfuscator PROPERTIES
    UNITY_BUILD      ON
    UNITY_BUILD_MODE GROUP
  )
  foreach(_dir IN LISTS KAGURA_PASS_DIRS)
    string(TOLOWER "${_dir}" _group)
    set_source_files_properties(${KAGURA_GROUP_${_dir}}
      PROPERTIES UNITY_GROUP "kagura_${_group}")
  endforeach()
endif()
