//===-- VMObfuscation.cpp - VM-based code virtualization pass -------------===//
//
// Transforms selected functions into bytecode executed by kagura's custom
// stack-based VM interpreter (runtime/vm_interpreter.c).
//
// Pipeline per function:
//   1. Lower the function's IR instructions to kagura VM opcodes.
//   2. Encode the bytecode as a constant array in the module.
//   3. XOR-encrypt the bytecode with a per-function random key.
//   4. Replace the function body with a trampoline that:
//        a. Decrypts the bytecode at runtime.
//        b. Packs arguments into a uint64_t array.
//        c. Calls kagura_vm_execute(bytecode, size, args, nargs).
//        d. Returns the result.
//
// Supported IR instructions:
//   BinaryOperator, ICmpInst, BranchInst (cond/uncond), ReturnInst,
//   LoadInst, StoreInst, ZExtInst, SExtInst, TruncInst,
//   AllocaInst (via pointer-to-integer encoding), CallInst (direct).
//
// Limitations (current):
//   - Floating-point operations are not virtualized.
//   - Exception handling (invoke/landingpad) is skipped.
//   - Functions with >16 arguments are skipped.
//   - Indirect calls are not supported.
//
//===----------------------------------------------------------------------===//

#include "kagura/Passes.h"
#include "kagura/Utils.h"
#include "kagura/VM.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <map>
#include <vector>

using namespace llvm;

namespace kagura {

// ── Bytecode emitter ────────────────────────────────────────────────────────

class BytecodeEmitter {
public:
  std::vector<uint8_t> BC;

  void emit8 (uint8_t  v) { BC.push_back(v); }
  void emit16(uint16_t v) {
    BC.push_back(v & 0xFF);
    BC.push_back((v >> 8) & 0xFF);
  }
  void emit32(uint32_t v) {
    for (int i = 0; i < 4; ++i) { BC.push_back(v & 0xFF); v >>= 8; }
  }
  void emit64(uint64_t v) {
    for (int i = 0; i < 8; ++i) { BC.push_back(v & 0xFF); v >>= 8; }
  }

  // Emit push for a 64-bit immediate, choosing smallest encoding
  void emitPushImm(uint64_t v) {
    if (v <= 0xFF) {
      emit8(vm::OP_PUSH_IMM8); emit8((uint8_t)v);
    } else if (v <= 0xFFFF) {
      emit8(vm::OP_PUSH_IMM16); emit16((uint16_t)v);
    } else if (v <= 0xFFFFFFFF) {
      emit8(vm::OP_PUSH_IMM32); emit32((uint32_t)v);
    } else {
      emit8(vm::OP_PUSH_IMM64); emit64(v);
    }
  }

  // Reserve a 32-bit jump target slot; returns offset of the slot
  uint32_t emitJmpPlaceholder(uint8_t jmpOp) {
    emit8(jmpOp);
    uint32_t off = BC.size();
    emit32(0xFFFFFFFF); // placeholder
    return off;
  }

  // Patch a previously reserved jump target
  void patchJmp(uint32_t slotOffset, uint32_t target) {
    BC[slotOffset]     =  target        & 0xFF;
    BC[slotOffset + 1] = (target >>  8) & 0xFF;
    BC[slotOffset + 2] = (target >> 16) & 0xFF;
    BC[slotOffset + 3] = (target >> 24) & 0xFF;
  }

  uint32_t size() const { return (uint32_t)BC.size(); }
};

// ── Value → virtual register mapper ─────────────────────────────────────────

class RegMap {
  std::map<Value *, uint8_t> Map;
  uint8_t Next = 0;
  bool Exhausted = false;
public:
  bool has(Value *V) const { return Map.count(V); }

  /// Allocates a virtual register for V, saturating when they run out.
  ///
  /// The interpreter has vm::kNumRegs registers and no spill mechanism, so a
  /// function with more virtualisable values than that cannot be lowered at
  /// all.  This used to assert, which aborted assertions-enabled builds on any
  /// large function — and, worse, in an NDEBUG build the assert vanished and
  /// the mapper happily handed out indices past the end of VMState::regs[],
  /// so the interpreter scribbled over adjacent state at run time.
  ///
  /// Now allocation stops at the limit and raises exhausted(); virtualize()
  /// checks that and throws the bytecode away, leaving the function untouched.
  uint8_t get(Value *V) {
    auto It = Map.find(V);
    if (It != Map.end()) return It->second;
    if (Next >= vm::kNumRegs) {
      Exhausted = true;
      return 0;
    }
    Map[V] = Next;
    return Next++;
  }

  void set(Value *V, uint8_t R) { Map[V] = R; }

  /// True if get() was asked for more registers than the VM has.
  bool exhausted() const { return Exhausted; }
};

// ── Instruction lowering ─────────────────────────────────────────────────────

// Returns the VM opcode for a binary operator, or 0xFF if unsupported
static uint8_t binaryOpcode(unsigned LLVMOpcode) {
  switch (LLVMOpcode) {
  case Instruction::Add:  return vm::OP_ADD;
  case Instruction::Sub:  return vm::OP_SUB;
  case Instruction::Mul:  return vm::OP_MUL;
  case Instruction::UDiv: return vm::OP_UDIV;
  case Instruction::SDiv: return vm::OP_SDIV;
  case Instruction::URem: return vm::OP_UREM;
  case Instruction::SRem: return vm::OP_SREM;
  case Instruction::And:  return vm::OP_AND;
  case Instruction::Or:   return vm::OP_OR;
  case Instruction::Xor:  return vm::OP_XOR;
  case Instruction::Shl:  return vm::OP_SHL;
  case Instruction::LShr: return vm::OP_LSHR;
  case Instruction::AShr: return vm::OP_ASHR;
  default: return 0xFF;
  }
}

static uint8_t icmpOpcode(CmpInst::Predicate P) {
  switch (P) {
  case CmpInst::ICMP_EQ:  return vm::OP_ICMP_EQ;
  case CmpInst::ICMP_NE:  return vm::OP_ICMP_NE;
  case CmpInst::ICMP_ULT: return vm::OP_ICMP_ULT;
  case CmpInst::ICMP_ULE: return vm::OP_ICMP_ULE;
  case CmpInst::ICMP_UGT: return vm::OP_ICMP_UGT;
  case CmpInst::ICMP_UGE: return vm::OP_ICMP_UGE;
  case CmpInst::ICMP_SLT: return vm::OP_ICMP_SLT;
  case CmpInst::ICMP_SLE: return vm::OP_ICMP_SLE;
  case CmpInst::ICMP_SGT: return vm::OP_ICMP_SGT;
  case CmpInst::ICMP_SGE: return vm::OP_ICMP_SGE;
  default: return 0xFF;
  }
}

// Emit "push value V onto stack" using either an immediate or a register load
static bool emitPushValue(Value *V, BytecodeEmitter &E, RegMap &RM,
                           const std::map<Argument *, uint8_t> &ArgIdx) {
  if (auto *CI = dyn_cast<ConstantInt>(V)) {
    E.emitPushImm(CI->getZExtValue());
    return true;
  }
  if (auto *A = dyn_cast<Argument>(V)) {
    auto It = ArgIdx.find(A);
    if (It == ArgIdx.end()) return false;
    E.emit8(vm::OP_LOAD_ARG);
    E.emit8(It->second);
    return true;
  }
  if (!RM.has(V)) return false;
  E.emit8(vm::OP_PUSH_REG);
  E.emit8(RM.get(V));
  return true;
}

// ── Function virtualizer ─────────────────────────────────────────────────────

static bool canVirtualize(Function &F) {
  if (F.isDeclaration()) return false;
  if (F.arg_size() > vm::kNumRegs) return false;
  // Skip functions with unsupported terminators or instructions
  for (auto &BB : F) {
    for (auto &I : BB) {
      if (isa<InvokeInst>(&I) || isa<IndirectBrInst>(&I) ||
          isa<CallBrInst>(&I))
        return false;
      // Skip FP for now
      if (I.getType()->isFloatingPointTy()) return false;
      // Skip functions that contain calls to external functions;
      // we only support direct calls to other virtualized/simple functions
      if (auto *CI = dyn_cast<CallInst>(&I)) {
        Function *Callee = CI->getCalledFunction();
        if (!Callee || Callee->isDeclaration())
          return false;
      }
    }
  }
  return true;
}

static std::vector<uint8_t> virtualize(Function &F) {
  BytecodeEmitter E;
  RegMap RM;

  // Map arguments to indices
  std::map<Argument *, uint8_t> ArgIdx;
  uint8_t AI = 0;
  for (auto &A : F.args())
    ArgIdx[&A] = AI++;

  // Map basic blocks to bytecode offsets (two-pass: first collect, then patch)
  std::map<BasicBlock *, uint32_t> BBOffset;
  std::vector<std::pair<uint32_t, BasicBlock *>> JmpPatches; // {slot_offset, target_BB}

  // First pass: emit bytecode, record block offsets, leave jumps as placeholders
  for (auto &BB : F) {
    BBOffset[&BB] = E.size();

    for (auto &I : BB) {
      if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
        uint8_t opc = binaryOpcode(BO->getOpcode());
        if (opc == 0xFF) { E.emit8(vm::OP_NOP); continue; }
        if (!emitPushValue(BO->getOperand(0), E, RM, ArgIdx)) continue;
        if (!emitPushValue(BO->getOperand(1), E, RM, ArgIdx)) continue;
        E.emit8(opc);
        // Store result
        uint8_t r = RM.get(&I);
        E.emit8(vm::OP_POP_REG); E.emit8(r);
        continue;
      }
      if (auto *CI = dyn_cast<ICmpInst>(&I)) {
        uint8_t opc = icmpOpcode(CI->getPredicate());
        if (opc == 0xFF) { E.emit8(vm::OP_NOP); continue; }
        if (!emitPushValue(CI->getOperand(0), E, RM, ArgIdx)) continue;
        if (!emitPushValue(CI->getOperand(1), E, RM, ArgIdx)) continue;
        E.emit8(opc);
        uint8_t r = RM.get(&I);
        E.emit8(vm::OP_POP_REG); E.emit8(r);
        continue;
      }
      if (auto *RI = dyn_cast<ReturnInst>(&I)) {
        if (RI->getReturnValue()) {
          if (!emitPushValue(RI->getReturnValue(), E, RM, ArgIdx)) {
            E.emitPushImm(0);
          }
          E.emit8(vm::OP_RET);
        } else {
          E.emit8(vm::OP_RET_VOID);
        }
        continue;
      }
      if (auto *BI = dyn_cast<BranchInst>(&I)) {
        if (BI->isUnconditional()) {
          uint32_t slot = E.emitJmpPlaceholder(vm::OP_JMP);
          JmpPatches.push_back({slot, BI->getSuccessor(0)});
        } else {
          // Conditional: JNZ true_target; fall through to false
          if (!emitPushValue(BI->getCondition(), E, RM, ArgIdx))
            E.emitPushImm(0);
          uint32_t slot = E.emitJmpPlaceholder(vm::OP_JNZ);
          JmpPatches.push_back({slot, BI->getSuccessor(0)});
          // Unconditional jump to false target
          uint32_t slot2 = E.emitJmpPlaceholder(vm::OP_JMP);
          JmpPatches.push_back({slot2, BI->getSuccessor(1)});
        }
        continue;
      }
      if (auto *LI = dyn_cast<LoadInst>(&I)) {
        if (!emitPushValue(LI->getPointerOperand(), E, RM, ArgIdx)) continue;
        unsigned bits = LI->getType()->isIntegerTy()
                            ? LI->getType()->getIntegerBitWidth() : 64;
        uint8_t opc = (bits <= 8)  ? vm::OP_LOAD8
                    : (bits <= 16) ? vm::OP_LOAD16
                    : (bits <= 32) ? vm::OP_LOAD32
                                   : vm::OP_LOAD64;
        E.emit8(opc);
        uint8_t r = RM.get(&I);
        E.emit8(vm::OP_POP_REG); E.emit8(r);
        continue;
      }
      if (auto *SI = dyn_cast<StoreInst>(&I)) {
        if (!emitPushValue(SI->getValueOperand(), E, RM, ArgIdx)) continue;
        if (!emitPushValue(SI->getPointerOperand(), E, RM, ArgIdx)) continue;
        unsigned bits = SI->getValueOperand()->getType()->isIntegerTy()
                            ? SI->getValueOperand()->getType()->getIntegerBitWidth()
                            : 64;
        uint8_t opc = (bits <= 8)  ? vm::OP_STORE8
                    : (bits <= 16) ? vm::OP_STORE16
                    : (bits <= 32) ? vm::OP_STORE32
                                   : vm::OP_STORE64;
        E.emit8(opc);
        continue;
      }
      if (auto *ZE = dyn_cast<ZExtInst>(&I)) {
        if (!emitPushValue(ZE->getOperand(0), E, RM, ArgIdx)) continue;
        E.emit8(vm::OP_ZEXT);
        uint8_t r = RM.get(&I);
        E.emit8(vm::OP_POP_REG); E.emit8(r);
        continue;
      }
      if (auto *SE = dyn_cast<SExtInst>(&I)) {
        if (!emitPushValue(SE->getOperand(0), E, RM, ArgIdx)) continue;
        E.emit8(vm::OP_SEXT);
        E.emit8((uint8_t)SE->getOperand(0)->getType()->getIntegerBitWidth());
        uint8_t r = RM.get(&I);
        E.emit8(vm::OP_POP_REG); E.emit8(r);
        continue;
      }
      if (auto *TR = dyn_cast<TruncInst>(&I)) {
        if (!emitPushValue(TR->getOperand(0), E, RM, ArgIdx)) continue;
        E.emit8(vm::OP_TRUNC);
        E.emit8((uint8_t)TR->getType()->getIntegerBitWidth());
        uint8_t r = RM.get(&I);
        E.emit8(vm::OP_POP_REG); E.emit8(r);
        continue;
      }
      // Default: emit NOP for unsupported instructions
      E.emit8(vm::OP_NOP);
    }
  }

  // The function needed more virtual registers than the interpreter has, so
  // the bytecode emitted above aliases registers and would compute garbage.
  // Discard it; the caller treats an empty result as "leave this one alone".
  if (RM.exhausted())
    return {};

  // Second pass: patch jump targets
  for (auto &[Slot, BB] : JmpPatches) {
    auto It = BBOffset.find(BB);
    if (It != BBOffset.end())
      E.patchJmp(Slot, It->second);
  }

  return E.BC;
}

// ── LLVM pass ────────────────────────────────────────────────────────────────

// Replace the function body with a VM trampoline
static bool buildTrampoline(Function &F, ArrayRef<uint8_t> Bytecode,
                              PRNG &RNG) {
  Module *M     = F.getParent();
  LLVMContext &Ctx = M->getContext();

  auto *Int8Ty  = Type::getInt8Ty(Ctx);
  auto *Int32Ty = Type::getInt32Ty(Ctx);
  auto *Int64Ty = Type::getInt64Ty(Ctx);
  auto *PtrTy   = PointerType::getUnqual(Ctx);

  // XOR-encrypt the bytecode
  uint64_t BCLen = Bytecode.size();
  uint64_t Key   = RNG.next();
  std::vector<uint8_t> Enc(BCLen);
  for (uint64_t I = 0; I < BCLen; ++I)
    Enc[I] = Bytecode[I] ^ (uint8_t)((Key >> (8 * (I % 8))) & 0xFF);

  // Emit encrypted bytecode as a mutable global
  std::vector<Constant *> EncBytes;
  EncBytes.reserve(BCLen);
  for (uint8_t B : Enc)
    EncBytes.push_back(ConstantInt::get(Int8Ty, B));
  auto *ArrTy   = ArrayType::get(Int8Ty, BCLen);
  auto *EncConst = ConstantArray::get(ArrTy, EncBytes);
  std::string Suffix = std::to_string(RNG.next32());
  auto *BCGlobal = new GlobalVariable(*M, ArrTy, /*isConst=*/false,
                                       GlobalValue::PrivateLinkage, EncConst,
                                       "kagura_vm_bc_" + Suffix);

  // Key global
  auto *KeyGV = new GlobalVariable(*M, Int64Ty, true,
                                    GlobalValue::PrivateLinkage,
                                    ConstantInt::get(Int64Ty, Key),
                                    "kagura_vm_key_" + Suffix);

  // Declare kagura_vm_execute
  auto *ExecFTy = FunctionType::get(Int64Ty,
                                     {PtrTy, Int32Ty, PtrTy, Int32Ty}, false);
  auto *ExecFn  = M->getOrInsertFunction("kagura_vm_execute", ExecFTy).getCallee();

  // Clear old function body and build trampoline
  F.deleteBody();
  auto *Entry = BasicBlock::Create(Ctx, "entry", &F);
  IRBuilder<> B(Entry);

  // Decrypt bytecode at call time: XOR key back
  // (simple loop inserted inline)
  auto *Len  = ConstantInt::get(Int64Ty, BCLen);
  auto *KeyV = B.CreateLoad(Int64Ty, KeyGV, "key");
  auto *IdxA = B.CreateAlloca(Int64Ty, nullptr, "idx");
  B.CreateStore(ConstantInt::get(Int64Ty, 0), IdxA);

  auto *LoopBB  = BasicBlock::Create(Ctx, "dec.loop", &F);
  auto *BodyBB  = BasicBlock::Create(Ctx, "dec.body", &F);
  auto *AfterBB = BasicBlock::Create(Ctx, "after.dec", &F);

  B.CreateBr(LoopBB);
  {
    IRBuilder<> LB(LoopBB);
    auto *Idx = LB.CreateLoad(Int64Ty, IdxA, "i");
    LB.CreateCondBr(LB.CreateICmpULT(Idx, Len), BodyBB, AfterBB);
  }
  {
    IRBuilder<> BB2(BodyBB);
    auto *Idx    = BB2.CreateLoad(Int64Ty, IdxA, "i");
    auto *KShift = BB2.CreateURem(Idx, ConstantInt::get(Int64Ty, 8));
    auto *KByte  = BB2.CreateTrunc(
        BB2.CreateLShr(KeyV, BB2.CreateMul(KShift,
                                            ConstantInt::get(Int64Ty, 8))),
        Int8Ty);
    auto *Ptr = BB2.CreateInBoundsGEP(ArrTy, BCGlobal,
                                       {ConstantInt::get(Int64Ty, 0), Idx});
    auto *Cur = BB2.CreateLoad(Int8Ty, Ptr);
    BB2.CreateStore(BB2.CreateXor(Cur, KByte), Ptr);
    BB2.CreateStore(BB2.CreateAdd(Idx, ConstantInt::get(Int64Ty, 1)), IdxA);
    BB2.CreateBr(LoopBB);
  }

  B.SetInsertPoint(AfterBB);

  // Pack arguments into uint64_t array on the stack
  uint32_t NArgs = F.arg_size();
  Value *ArgsPtr = ConstantPointerNull::get(PtrTy);
  if (NArgs > 0) {
    auto *ArgArrTy = ArrayType::get(Int64Ty, NArgs);
    auto *ArgAlloc = B.CreateAlloca(ArgArrTy, nullptr, "vmargs");
    uint32_t Idx2  = 0;
    for (auto &Arg : F.args()) {
      Value *V = &Arg;
      if (!V->getType()->isIntegerTy())
        V = ConstantInt::get(Int64Ty, 0);
      else
        V = B.CreateZExtOrBitCast(V, Int64Ty);
      auto *Ptr = B.CreateInBoundsGEP(ArgArrTy, ArgAlloc,
                                       {ConstantInt::get(Int32Ty, 0),
                                        ConstantInt::get(Int32Ty, Idx2++)});
      B.CreateStore(V, Ptr);
    }
    ArgsPtr = ArgAlloc;
  }

  // Call the interpreter
  auto *BCPtr  = B.CreatePointerCast(BCGlobal, PtrTy);
  auto *Result = B.CreateCall(ExecFTy, ExecFn,
                               {BCPtr,
                                ConstantInt::get(Int32Ty, BCLen),
                                ArgsPtr,
                                ConstantInt::get(Int32Ty, NArgs)},
                               "vm.result");

  // Return
  Type *RetTy = F.getReturnType();
  if (RetTy->isVoidTy()) {
    B.CreateRetVoid();
  } else if (RetTy->isIntegerTy()) {
    B.CreateRet(B.CreateTrunc(Result, RetTy));
  } else {
    B.CreateRet(UndefValue::get(RetTy));
  }

  return true;
}

PreservedAnalyses VMObfuscationPass::run(Function &F,
                                          FunctionAnalysisManager &) {
  // C.1: The VM interpreter uses platform-specific indirect dispatch and
  // function pointer manipulation that does not lower correctly on Wasm.
  if (kagura::isWasmTarget(*F.getParent()))
    return PreservedAnalyses::all();

  if (!shouldObfuscate(F, "vm")) return PreservedAnalyses::all();
  if (!canVirtualize(F)) return PreservedAnalyses::all();

  auto &RNG = getModulePRNG();
  auto BC   = virtualize(F);
  if (BC.empty()) return PreservedAnalyses::all();

  buildTrampoline(F, BC, RNG);
  return PreservedAnalyses::none();
}

} // namespace kagura
