# kagura-opt: standalone bitcode processing tool
#
# Shared mode (default): loads libKaguraObfuscator at runtime via
# PassPlugin::Load() — no static link against the MODULE.  This avoids the
# MODULE_LIBRARY linkage restriction.
#
# Static mode (KAGURA_PLUGIN_STATIC): links the passes in and calls
# getKaguraPluginInfo() directly.  Used where LLVM has no loadable-module
# support — notably Windows/MSVC, where this tool is the only way to run the
# passes since -fpass-plugin is unavailable.
#
# We use add_llvm_executable (from LLVM's AddLLVM.cmake) instead of plain
# add_executable so that llvm_update_compile_flags() is applied.  Without it,
# the LLVM 17 libc++ headers on macOS are not found before the macOS SDK C
# headers, causing cascade errors from <cstddef>, <cstdint>, etc.

add_llvm_executable(kagura-opt
  kagura-opt.cpp
)

# Link LLVM exactly once.  When LLVM is built with LLVM_LINK_LLVM_DYLIB=ON
# (e.g. Homebrew), add_llvm_executable already links libLLVM.dylib; also adding
# the static component archives (libLLVMSupport.a, ...) links a *second* copy of
# the cl::opt command-line registry into this binary.  The kagura plugin, loaded
# at runtime, registers its -kagura-* options into the dylib's registry, so with
# a duplicate static registry cl::ParseCommandLineOptions() here would never see
# them.  Link the shared libLLVM in dylib mode, static components otherwise.
if(LLVM_LINK_LLVM_DYLIB)
  set(KAGURA_OPT_LLVM_LIBS LLVM)
else()
  # Analysis and TransformUtils are what the passes themselves need: the static
  # KaguraObfuscator archive does not link LLVM, so the executable has to cover
  # its dependencies too.
  llvm_map_components_to_libnames(KAGURA_OPT_LLVM_LIBS
    Core
    Support
    IRReader
    BitWriter
    BitReader
    Passes
    Analysis
    TransformUtils
  )
endif()

target_link_libraries(kagura-opt PRIVATE
  ${KAGURA_OPT_LLVM_LIBS}
)

# Static mode: link the passes in and switch kagura-opt to the direct
# getKaguraPluginInfo() call.  KaguraObfuscator must come before the LLVM
# component libs it depends on, which target_link_libraries already handles.
if(KAGURA_PLUGIN_STATIC)
  target_compile_definitions(kagura-opt PRIVATE KAGURA_STATIC_PLUGIN=1)
  target_link_libraries(kagura-opt PRIVATE KaguraObfuscator)
endif()

target_include_directories(kagura-opt PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${LLVM_INCLUDE_DIRS}
)

# Place alongside the plugin so the auto-detection logic in kagura-opt.cpp
# can find libKaguraObfuscator in <exe_dir>/../lib/.
set_target_properties(kagura-opt PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# kagura-opt needs the plugin to be built first (loaded at runtime).
add_dependencies(kagura-opt KaguraObfuscator)

install(TARGETS kagura-opt DESTINATION bin)
