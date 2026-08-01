# Fuzzing — libFuzzer-based crash detection for kagura passes.
#
# Each fuzzer takes arbitrary bytes as input, interprets them as LLVM bitcode
# (or a simplified IR representation), runs a kagura pass, and checks:
#   1. The pass does not crash (segfault / abort).
#   2. The pass does not corrupt the IR module (runs verifyModule).
#   3. The pass terminates within a reasonable time (libFuzzer timeout).
#
# Requires a clang build with -fsanitize=fuzzer (LLVM >= 6).
# Set KAGURA_BUILD_FUZZ=ON at cmake configure time to enable.


if(NOT KAGURA_BUILD_FUZZ)
  return()
endif()

# Check for fuzzer support
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-fsanitize=fuzzer" HAS_FUZZER)
if(NOT HAS_FUZZER)
  message(WARNING "[kagura] -fsanitize=fuzzer not supported; skipping fuzz targets")
  return()
endif()

message(STATUS "[kagura] Building libFuzzer fuzz targets")

set(FUZZ_FLAGS -fsanitize=fuzzer,address -O1 -g)

macro(kagura_add_fuzz_target NAME SOURCE)
  add_executable(fuzz_${NAME} ${SOURCE})
  target_link_libraries(fuzz_${NAME} PRIVATE KaguraObfuscator LLVMCore LLVMSupport
                         LLVMIRReader LLVMPasses LLVMBitReader)
  target_include_directories(fuzz_${NAME} PRIVATE
    ${PROJECT_SOURCE_DIR}/include ${LLVM_INCLUDE_DIRS})
  target_compile_options(fuzz_${NAME} PRIVATE ${FUZZ_FLAGS})
  target_link_options(fuzz_${NAME} PRIVATE ${FUZZ_FLAGS})
  set_target_properties(fuzz_${NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/fuzz")
endmacro()

kagura_add_fuzz_target(fla    fuzz_fla.cpp)
kagura_add_fuzz_target(bcf    fuzz_bcf.cpp)
kagura_add_fuzz_target(sub    fuzz_sub.cpp)
kagura_add_fuzz_target(str    fuzz_str.cpp)
kagura_add_fuzz_target(mvo    fuzz_mvo.cpp)
kagura_add_fuzz_target(pe     fuzz_pe.cpp)
kagura_add_fuzz_target(bbr    fuzz_bbr.cpp)
kagura_add_fuzz_target(vtp    fuzz_vtp.cpp)
kagura_add_fuzz_target(fsplit fuzz_fsplit.cpp)
kagura_add_fuzz_target(vm     fuzz_vm.cpp)
