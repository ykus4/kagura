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
  include(CMakePackageConfigHelpers)

  set(KAGURA_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/Kagura)

  # The pass plugin. A loadable module is a LIBRARY on ELF/Mach-O; on Windows a
  # static plugin build produces an ARCHIVE instead, so list both destinations.
  #
  # Deliberately NOT in the export set. A MODULE library cannot be linked, so
  # CMake refuses to export one, and even in the static-plugin build the plugin
  # is not something a consumer links: it is handed to clang -fpass-plugin= or
  # opt --load-pass-plugin= by path. KaguraConfig.cmake resolves that path into
  # the Kagura_PLUGIN variable instead.
  if(TARGET KaguraObfuscator)
    install(TARGETS KaguraObfuscator
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  endif()

  # The runtime the obfuscated binary links against.
  if(TARGET kagura_runtime)
    # The exported interface cannot name a build-tree path: an installed
    # package is consumed from another machine, where ${PROJECT_SOURCE_DIR}
    # does not exist. Without this split install(EXPORT) refuses the target
    # outright ("INTERFACE_INCLUDE_DIRECTORIES ... which is prefixed in the
    # source directory"), which is why there was no export set to begin with.
    #
    # Set here rather than in runtime/CMakeLists.txt so the whole export
    # contract — what is installed, under what name, with which usage
    # requirements — stays readable in one file.
    set_property(TARGET kagura_runtime PROPERTY INTERFACE_INCLUDE_DIRECTORIES
      "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
      "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

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
  # consumer building the runtime from source needs. runtime.h is the curated
  # portable subset of runtime/internal.h — the tamper hook, the soft-response
  # API and the kagura_check_* predicates — which docs/runtime.md and four
  # cookbook pages tell readers to #include; until it was installed that
  # instruction only worked from a source checkout. It is pure C99 and needs no
  # LLVM header, which is the line this list draws. The podspec and
  # Package.swift already draw it in the same place.
  install(FILES
            ${PROJECT_SOURCE_DIR}/include/kagura/game_protect.h
            ${PROJECT_SOURCE_DIR}/include/kagura/runtime.h
            ${PROJECT_SOURCE_DIR}/include/kagura/VM.h
            ${PROJECT_SOURCE_DIR}/include/kagura/VMOpcodes.def
          DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kagura)

  # The JSON policy profiles the integrations reference by path.
  if(EXISTS ${PROJECT_SOURCE_DIR}/integration/profiles)
    install(DIRECTORY ${PROJECT_SOURCE_DIR}/integration/profiles
            DESTINATION ${CMAKE_INSTALL_DATADIR}/kagura
            FILES_MATCHING PATTERN "*.json")
  endif()

  # ---- The CMake package -----------------------------------------------------
  #
  # `EXPORT KaguraTargets` was already spelled on the install(TARGETS) calls
  # above, but nothing ever installed the export set and there was no
  # KaguraConfig.cmake or version file anywhere in the tree. CMake accepts an
  # unused export set silently, so the release tarballs contained no CMake
  # package at all and `find_package(Kagura)` could not work — the one thing
  # the export name suggested was supported.
  if(TARGET kagura_runtime)
    install(EXPORT KaguraTargets
            NAMESPACE Kagura::
            DESTINATION ${KAGURA_CMAKE_DIR})
  endif()

  configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/cmake/KaguraConfig.cmake.in
    ${PROJECT_BINARY_DIR}/KaguraConfig.cmake
    INSTALL_DESTINATION ${KAGURA_CMAKE_DIR}
    PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_DATADIR)

  # SameMajorVersion would promise ABI stability across 0.x releases, which
  # this project does not offer while the VM bytecode contract is still moving.
  write_basic_package_version_file(
    ${PROJECT_BINARY_DIR}/KaguraConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMinorVersion)

  install(FILES
            ${PROJECT_BINARY_DIR}/KaguraConfig.cmake
            ${PROJECT_BINARY_DIR}/KaguraConfigVersion.cmake
          DESTINATION ${KAGURA_CMAKE_DIR})
endfunction()
