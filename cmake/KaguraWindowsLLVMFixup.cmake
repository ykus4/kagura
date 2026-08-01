# KaguraWindowsLLVMFixup.cmake — work around absolute paths baked into the
# official Windows LLVM release.
#
# The MSVC-targeted clang+llvm tarball records absolute paths from the machine
# that built it in its exported link interfaces — most visibly the DIA SDK's
# diaguids.lib, under a Visual Studio 2019 install that exists nowhere else.
# Linking anything against those components then fails at generate time with
# "missing and no known rule to make it", before a single file is compiled.
#
# Drop link-interface entries that name an absolute path which does not exist.
# If one turns out to be genuinely needed, the link fails with an unresolved
# symbol — a far more actionable error than a missing-file one — and the STATUS
# lines below say exactly what was removed.

include_guard(GLOBAL)

function(kagura_prune_stale_llvm_link_paths)
  if(NOT WIN32)
    return()
  endif()
  foreach(_target IN LISTS LLVM_AVAILABLE_LIBS)
    if(NOT TARGET ${_target})
      continue()
    endif()
    get_target_property(_libs ${_target} INTERFACE_LINK_LIBRARIES)
    if(NOT _libs)
      continue()
    endif()
    set(_kept "")
    foreach(_lib IN LISTS _libs)
      if(IS_ABSOLUTE "${_lib}" AND NOT EXISTS "${_lib}")
        message(STATUS "[kagura] ${_target}: dropping missing link dependency ${_lib}")
      else()
        list(APPEND _kept "${_lib}")
      endif()
    endforeach()
    set_target_properties(${_target} PROPERTIES INTERFACE_LINK_LIBRARIES "${_kept}")
  endforeach()
endfunction()
