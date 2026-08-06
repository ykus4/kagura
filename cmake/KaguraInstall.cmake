# KaguraInstall.cmake — install rules for the shipped artifacts.
#
# Only kagura-opt had an install() rule, so .github/workflows/release.yml
# assembled release bundles by hand-copying build-tree paths
# (build/lib/Transforms/KaguraObfuscator.${plugin-ext},
# build/runtime/${runtime-prefix}kagura_runtime.a, cp -r include/kagura), with
# a per-platform matrix of extension and prefix variables that existed purely
# to paper over the missing rules. With these in place that whole staging step
# is `cmake --install build --prefix "$BUNDLE_DIR"`.

include_guard(GLOBAL)

function(kagura_add_install_rules)
  include(GNUInstallDirs)

  # The pass plugin. A loadable module is a LIBRARY on ELF/Mach-O; on Windows a
  # static plugin build produces an ARCHIVE instead, so list both destinations.
  if(TARGET KaguraObfuscator)
    install(TARGETS KaguraObfuscator
            EXPORT  KaguraTargets
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  endif()

  # The runtime the obfuscated binary links against.
  if(TARGET kagura_runtime)
    install(TARGETS kagura_runtime
            EXPORT  KaguraTargets
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
  endif()

  # Public headers, listed rather than globbed.
  #
  # `FILES_MATCHING PATTERN "*.h"` over the whole directory shipped the LLVM
  # pass-plugin headers — Options.h, Passes/, Utils.h — to consumers who have
  # no LLVM to include, and it stopped even being self-consistent once those
  # headers started expanding a .def: the pattern excluded PassRegistry.def and
  # VMOpcodes.def, so the installed Options.h could not be included at all.
  #
  # game_protect.h is the consumer-facing interface (the Protected<T>
  # template). VM.h plus the .def it expands are the bytecode contract, which a
  # consumer building the runtime from source needs. The podspec and Package.swift
  # already draw the line in this same place.
  install(FILES
            ${PROJECT_SOURCE_DIR}/include/kagura/game_protect.h
            ${PROJECT_SOURCE_DIR}/include/kagura/VM.h
            ${PROJECT_SOURCE_DIR}/include/kagura/VMOpcodes.def
          DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kagura)

  # The JSON policy profiles the integrations reference by path.
  if(EXISTS ${PROJECT_SOURCE_DIR}/integration/profiles)
    install(DIRECTORY ${PROJECT_SOURCE_DIR}/integration/profiles
            DESTINATION ${CMAKE_INSTALL_DATADIR}/kagura
            FILES_MATCHING PATTERN "*.json")
  endif()
endfunction()
