#pragma once

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include <cstdint>
#include <string>
#include <vector>

namespace kagura {

// ---- Audit log helpers ----

/// Attach a kagura_obfuscated metadata node to F recording the pass name.
/// Multiple calls accumulate pass names in a single MDTuple.
void markObfuscated(llvm::Function &F, llvm::StringRef PassName);

// ---- Annotation helpers ----

/// Returns true if F has the given annotation attribute.
bool hasAnnotation(llvm::Function &F, llvm::StringRef Attr);

/// Returns true if F should be obfuscated by the pass identified by PassAttr.
/// Respects both module-level flags and per-function annotations:
///   annotate("kagura_<passAttr>")   -> force enable
///   annotate("kagura_no<passAttr>") -> force disable
bool shouldObfuscate(llvm::Function &F, llvm::StringRef PassAttr,
                     bool GlobalFlag);

/// Returns true if Name is a symbol kagura itself generated.
///
/// Passes must not obfuscate their own helpers, and SymbolMap must not report
/// them. Both checks used to be open-coded and had drifted apart — Utils.cpp
/// matched only "kagura_" while SymbolMap.cpp also matched "__kagura", so the
/// "__kg_*" helpers emitted by FunctionSplit and the "kagura.*" globals
/// emitted by EncryptedLookupTable and ControlFlowFlattening were re-obfuscated
/// by later passes. This recognises every prefix kagura actually emits.
bool isKaguraSymbol(llvm::StringRef Name);

// ---- Hashing ----

/// FNV-1a. Used both for compile-time integrity hashes that the C runtime
/// recomputes and for deriving stable IDs from symbol names, so the constants
/// must stay in sync with runtime/core/hash.c.
uint32_t fnv1a32(llvm::ArrayRef<uint8_t> Data);
uint32_t fnv1a32(llvm::StringRef S);
uint64_t fnv1a64(llvm::StringRef S);

/// Incremental FNV-1a-32, for callers that hash something other than a flat
/// byte range (opcode streams, for instance). Start from fnv1a32Init().
///
/// Note the two opcode hashes in this codebase deliberately differ:
/// BasicBlockChecksum feeds only the low byte of each opcode while AntiTamper
/// feeds all four. They are separate mechanisms with separate runtime
/// counterparts, so only the constants are shared here — unifying the
/// byte-feeding would change both hash values.
constexpr uint32_t fnv1a32Init() { return 0x811c9dc5u; }
constexpr uint32_t fnv1a32Update(uint32_t Hash, uint8_t Byte) {
  return (Hash ^ Byte) * 0x01000193u;
}

// ---- Module constructor priorities ----

/// Priorities for llvm::appendToGlobalCtors.
///
/// The ordering between kagura's constructors is a real correctness
/// constraint — string tables must be decrypted before anything reads them,
/// and the PAC key must exist before any signed pointer is authenticated —
/// but it used to live only in trailing comments next to seven bare integers.
/// Lower runs earlier.
enum class CtorPriority : int {
  SwiftString   = -1,    ///< Swift string tables: before all other ctors.
  RuntimeString = 0,     ///< XOR/AES string and CFString tables.
  AntiDebug     = 0,     ///< Anti-debug init; independent of the string tables.
  RTTI          = 100,   ///< vtable / typeinfo fixups.
  ObjCRemap     = 200,   ///< ObjC selector remap table registration.
  HwPAC         = 65533, ///< arm64e pointer-auth key.
  SwPAC         = 65534, ///< Software pointer-auth key.
  ThunkTable    = 65535, ///< Call-indirection thunk table.
  Honey         = 65535, ///< Decoy initialisation; ordering irrelevant.
};

/// Register Ctor in llvm.global_ctors at the given priority.
void appendKaguraCtor(llvm::Module &M, llvm::Function *Ctor, CtorPriority P);

// ---- Pseudo-random number generator ----

/// Simple splitmix64-based PRNG seeded once per compilation unit.
class PRNG {
public:
  explicit PRNG(uint64_t Seed = 0);
  uint64_t next();
  uint64_t nextRange(uint64_t Lo, uint64_t Hi); // [Lo, Hi)
  uint32_t next32();

private:
  uint64_t State;
};

/// Returns the module-level PRNG (seeded from -kagura-seed or system entropy).
PRNG &getModulePRNG();

// ---- IR helpers ----

/// Demote all PHI nodes in F to alloca/load/store (needed before flattening).
void demotePhis(llvm::Function &F);

/// Collects all basic blocks in F except entry (safe to iterate & mutate).
std::vector<llvm::BasicBlock *> getBlocks(llvm::Function &F);

/// Get or declare an external C function in M (idempotent).
llvm::Function *getOrDeclare(llvm::Module &M, llvm::StringRef Name,
                             llvm::FunctionType *FTy);

/// Create an InternalLinkage `void()` function named `Name` in `M` with a
/// single empty "entry" basic block — the shape every kagura module
/// constructor shares. The caller adds any function attributes, emits the body
/// and its terminator, and (for module ctors) registers it via
/// llvm::appendToGlobalCtors(). Retrieve the entry block with
/// `&F->getEntryBlock()`.
llvm::Function *createCtorFunction(llvm::Module &M, const llvm::Twine &Name);

// ---- Exception-handling safety ----

/// Returns true if F contains any invoke or landingpad instructions.
/// Passes that restructure the CFG must skip such functions unless they
/// explicitly handle exception-handling edges.
bool hasExceptionHandling(const llvm::Function &F);

/// Returns true if BB is a landing pad block (starts with LandingPadInst or
/// CleanupPadInst) or contains a catchpad/cleanuppad instruction.
bool isEHBlock(const llvm::BasicBlock &BB);

// ---- Target triple helpers ----

enum class TargetArch {
  ARM64,   // AArch64 (including arm64e)
  ARM64e,  // AArch64 with hardware PAC (apple-arm64e)
  ARMv7,   // 32-bit ARM
  X86_64,  // x86-64
  Wasm32,  // WebAssembly (32-bit linear memory)
  Wasm64,  // WebAssembly (64-bit linear memory)
  Other,
};

/// Return the module's target triple as a std::string.
/// Handles the getTargetTriple() API difference between LLVM versions:
///   LLVM 17-19: returns const std::string &
///   LLVM 20+  : returns const Triple &
std::string getModuleTriple(const llvm::Module &M);

/// Return the architecture of the module's target triple.
TargetArch getTargetArch(const llvm::Module &M);

/// Returns true if the module targets AArch64 (arm64 or arm64e).
bool isAArch64Target(const llvm::Module &M);

/// Returns true if the module targets arm64e (hardware PAC available).
bool isArm64eTarget(const llvm::Module &M);

/// Returns true if the module targets a 32-bit ARM device.
bool isARMv7Target(const llvm::Module &M);

/// Returns true if the module targets x86-64.
bool isX86_64Target(const llvm::Module &M);

/// Returns true if the module targets WebAssembly (wasm32 or wasm64).
/// Passes that use platform-specific syscalls, Mach-O sections, ELF/PE
/// structure, or hardware PAC must skip themselves on Wasm targets.
bool isWasmTarget(const llvm::Module &M);

// ---- String global collection ----

/// Collect all ConstantDataArray globals that look like strings, are used in
/// at least one function, and satisfy basic heuristics (length >= 4, no format
/// specifiers, etc.).  If StrictLinkage is true, only private/internal globals
/// are collected.
std::vector<llvm::GlobalVariable *>
collectStringGlobals(llvm::Module &M, bool StrictLinkage = false);

// ---- Global-variable use analysis ----

/// Returns true when every use of GV sits at an instruction use site where a
/// lazy-decrypt guard can be emitted.
///
/// Globals referenced from other global initializers are deliberately
/// excluded: there is no runtime insertion point that can guarantee the
/// encrypted bytes are decrypted before an initializer-derived pointer is
/// consumed. PHI users are excluded because the guard splits the block, which
/// would invalidate the PHI's incoming edges.
bool hasOnlyGuardableUses(const llvm::GlobalVariable *GV);

// ---- Lazy-decrypt guard ----

/// Emit, immediately before InsertBefore:
///
///     if (!FlagGV) { DecryptStub(); FlagGV = 1; }
///
/// so an encrypted global is decrypted at most once, on first use, rather than
/// on every path that reaches it. BBPrefix names the blocks the guard creates
/// ("lazy" for byte strings, "wlazy" for wide strings) purely so the IR stays
/// readable when both passes run.
void emitLazyGuard(llvm::Instruction *InsertBefore,
                   llvm::GlobalVariable *FlagGV,
                   llvm::Function *DecryptStub,
                   llvm::StringRef BBPrefix = "lazy");

// ---- Call rewriting ----

/// Replace CI with an otherwise identical call through NewCallee, preserving
/// the argument list, operand bundles, calling convention, parameter and
/// return attributes, tail-call kind, fast-math flags and debug location.
/// RAUWs and erases CI; returns the replacement.
///
/// Four passes open-coded this and one copy had already lost
/// copyFastMathFlags, silently dropping fast-math on rewritten calls.
llvm::CallInst *replaceCalleeWith(llvm::CallInst *CI,
                                  llvm::FunctionType *FTy,
                                  llvm::Value *NewCallee);

/// RAUW every use of Old with New except New's own use of Old.
///
/// The idiom for "wrap a value in a new instruction that consumes it" — e.g.
/// replacing loads with an XOR of the loaded value. Getting this wrong makes
/// the new instruction feed itself.
void replaceAllUsesExcept(llvm::Value *Old, llvm::Instruction *New);

// ---- Constant builders ----

/// Build a ConstantArray of i8 from raw bytes.
llvm::Constant *buildByteArrayConstant(llvm::LLVMContext &Ctx,
                                       llvm::ArrayRef<uint8_t> Data);

/// Create a private constant global holding the given byte data.
llvm::GlobalVariable *createPrivateByteGlobal(llvm::Module &M,
                                              llvm::ArrayRef<uint8_t> Data,
                                              llvm::StringRef Name,
                                              bool IsConstant = true);

/// Fill a buffer with random bytes from the module PRNG.
void fillRandomBytes(uint8_t *Out, size_t Len);

} // namespace kagura
