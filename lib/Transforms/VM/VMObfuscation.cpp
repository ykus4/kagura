//===-- VMObfuscation.cpp - VM-based code virtualization pass -------------===//
//
// Turns a function into an encrypted bytecode blob executed by kagura's stack
// VM (runtime/core/vm_interpreter.c).  The bytecode contract — opcodes, the
// one-byte width operands, and the canonical value representation — is
// documented in include/kagura/VM.h and must be read alongside this file.
//
// Pipeline per function:
//   1. Lower the function's IR to kagura VM opcodes.  Lowering is all-or-
//      nothing: anything the VM cannot express makes lower() fail and the
//      function is left completely untouched.
//   2. XOR-encrypt the bytecode with a per-function 64-bit key.
//   3. Replace the body with a trampoline that packs the arguments into a
//      uint64_t array and calls kagura_vm_execute(blob, size, args, nargs,
//      pool, npool, key).
//
// Why all-or-nothing matters
// --------------------------
// This pass used to emit OP_NOP for every instruction it did not recognise —
// PHI nodes, calls, GEPs, allocas, selects and switches all fell into that
// bucket — and to silently skip an instruction whose operand it could not
// materialise.  canVirtualize() nevertheless accepted such functions, so the
// bytecode for anything past straight-line arithmetic was semantic garbage.
// For a loop it was worse than garbage: a lowered `br i1 %cmp` whose condition
// had been dropped pushed a literal 0, so the VM took the same edge forever and
// the program hung with no output.  A shape the pass cannot lower must never
// reach the interpreter.
//
// What is supported
// -----------------
//   Types:        iN for N <= 64, pointers, and void as a return type.
//   Instructions: integer binops, icmp, select, freeze, load/store (1/2/4/8
//                 byte, non-atomic), zext/sext/trunc/ptrtoint/inttoptr/bitcast,
//                 getelementptr, static-size alloca, PHI (lowered to
//                 stack-based parallel copies on each edge), br, switch, ret,
//                 unreachable, and direct calls to non-variadic functions whose
//                 parameters and result are integers or pointers.
//   Intrinsics:   llvm.abs/smax/smin/umax/umin on scalar integers, lowered back
//                 to the compare-and-select they replaced.  llvm.lifetime.*,
//                 llvm.assume and llvm.donothing are semantic no-ops for us and
//                 are dropped.  Every other intrinsic is unsupported.
//
// Everything else — floating point, vectors, aggregates held in registers,
// invoke/landingpad, atomics, va_arg, indirect and variadic calls, byval/sret
// arguments, dynamic allocas — makes the function ineligible.
//
//===----------------------------------------------------------------------===//

#include "kagura/Passes/VM.h"
#include "kagura/Utils.h"
#include "kagura/VM.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ModRef.h"

#include <optional>
#include <vector>

using namespace llvm;

namespace kagura {

namespace {

// ── Bytecode emitter ────────────────────────────────────────────────────────

class BytecodeEmitter {
public:
  std::vector<uint8_t> BC;

  void emit8(uint8_t v) { BC.push_back(v); }
  void emit16(uint16_t v) {
    BC.push_back(v & 0xFF);
    BC.push_back((v >> 8) & 0xFF);
  }
  void emit32(uint32_t v) {
    for (int I = 0; I < 4; ++I) { BC.push_back(v & 0xFF); v >>= 8; }
  }
  void emit64(uint64_t v) {
    for (int I = 0; I < 8; ++I) { BC.push_back(v & 0xFF); v >>= 8; }
  }

  /// Push a 64-bit immediate using the shortest encoding.
  void emitPushImm(uint64_t V) {
    if (V <= 0xFF) {
      emit8(vm::OP_PUSH_IMM8);  emit8((uint8_t)V);
    } else if (V <= 0xFFFF) {
      emit8(vm::OP_PUSH_IMM16); emit16((uint16_t)V);
    } else if (V <= 0xFFFFFFFF) {
      emit8(vm::OP_PUSH_IMM32); emit32((uint32_t)V);
    } else {
      emit8(vm::OP_PUSH_IMM64); emit64(V);
    }
  }

  /// Emit a jump with an unresolved target; returns the offset of the operand.
  uint32_t emitJump(uint8_t JmpOp) {
    emit8(JmpOp);
    uint32_t Slot = size();
    emit32(0);
    return Slot;
  }

  void patchJump(uint32_t Slot, uint32_t Target) {
    for (unsigned I = 0; I < 4; ++I)
      BC[Slot + I] = (Target >> (8 * I)) & 0xFF;
  }

  uint32_t size() const { return (uint32_t)BC.size(); }
};

/// Everything buildTrampoline() needs from a successful lowering.
struct VMProgram {
  std::vector<uint8_t> BC;
  /// Constants the bytecode refers to by index: globals and callee addresses,
  /// which only the linker knows and so cannot be baked into the byte stream.
  std::vector<Constant *> Pool;
  /// Bytes of frame arena the function's allocas need.
  uint32_t FrameSize = 0;
};

// ── Type classification ─────────────────────────────────────────────────────

/// True if the VM can hold a value of this type in a 64-bit slot.
static bool isVMType(Type *T) {
  if (T->isPointerTy())
    return T->getPointerAddressSpace() == 0;
  return T->isIntegerTy() && T->getIntegerBitWidth() <= 64;
}

/// Bit width used for width-tagged opcodes: pointers behave as i64.
static unsigned vmWidth(Type *T) {
  return T->isPointerTy() ? 64 : T->getIntegerBitWidth();
}

/// Intrinsics with no effect on anything the VM models.
static bool isIgnorableIntrinsic(const CallInst *CI) {
  switch (CI->getIntrinsicID()) {
  case Intrinsic::lifetime_start:
  case Intrinsic::lifetime_end:
  case Intrinsic::assume:
  case Intrinsic::donothing:
  case Intrinsic::experimental_noalias_scope_decl:
    return true;
  default:
    return false;
  }
}

// ── Lowering ────────────────────────────────────────────────────────────────

/// Lowers one function to bytecode, or fails.
///
/// Every path that cannot be expressed calls fail(); the caller must check
/// the returned std::optional and leave the function alone when it is empty.
/// Nothing here mutates F.
class Lowerer {
public:
  Lowerer(Function &F)
      : F(F), DL(F.getParent()->getDataLayout()),
        Int64Ty(Type::getInt64Ty(F.getContext())) {}

  std::optional<VMProgram> lower() {
    if (!assignArgs() || !layoutFrame() || !assignRegs())
      return std::nullopt;
    if (!emitBody())
      return std::nullopt;

    for (auto &[Slot, BB] : BlockPatches) {
      auto It = BlockOffset.find(BB);
      if (It == BlockOffset.end())
        return std::nullopt;
      E.patchJump(Slot, It->second);
    }

    if (E.BC.empty() || E.BC.size() > vm::kMaxBCSize)
      return std::nullopt;

    VMProgram P;
    P.BC        = std::move(E.BC);
    P.Pool      = std::move(Pool);
    P.FrameSize = FrameSize;
    return P;
  }

private:
  Function &F;
  const DataLayout &DL;
  Type *Int64Ty;

  BytecodeEmitter E;
  bool Failed = false;

  DenseMap<const Argument *, unsigned> ArgIdx;
  DenseMap<const Value *, unsigned> Reg;
  DenseMap<const AllocaInst *, uint32_t> FrameOff;
  uint32_t FrameSize = 0;

  std::vector<Constant *> Pool;
  DenseMap<Constant *, unsigned> PoolIdx;

  DenseMap<const BasicBlock *, uint32_t> BlockOffset;
  std::vector<std::pair<uint32_t, const BasicBlock *>> BlockPatches;

  bool fail() { Failed = true; return false; }

  // ---- Preparation ---------------------------------------------------------

  bool assignArgs() {
    if (F.isVarArg() || F.arg_size() > 255)
      return fail();
    Type *RetTy = F.getReturnType();
    if (!RetTy->isVoidTy() && !isVMType(RetTy))
      return fail();
    unsigned Idx = 0;
    for (Argument &A : F.args()) {
      if (!isVMType(A.getType()))
        return fail();
      // These change the ABI in ways the generic uint64_t packing cannot
      // reproduce, even though the IR-level value is a plain pointer.
      if (A.hasByValAttr() || A.hasStructRetAttr() || A.hasInAllocaAttr() ||
          A.hasAttribute(Attribute::Preallocated) ||
          A.hasAttribute(Attribute::SwiftError) ||
          A.hasAttribute(Attribute::SwiftSelf) ||
          A.hasAttribute(Attribute::Nest))
        return fail();
      ArgIdx[&A] = Idx++;
    }
    return true;
  }

  /// Give every alloca a fixed offset in the interpreter's frame arena.
  ///
  /// A constant-size alloca outside the entry block gets one offset too, which
  /// re-uses the same address on every iteration.  That matches what LLVM's own
  /// alloca promotion does; a *dynamically* sized alloca has no such fixed
  /// layout and makes the function ineligible.
  bool layoutFrame() {
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        auto *AI = dyn_cast<AllocaInst>(&I);
        if (!AI)
          continue;
        if (AI->getType()->getPointerAddressSpace() != 0)
          return fail();
        auto Size = AI->getAllocationSize(DL);
        if (!Size || Size->isScalable())
          return fail();
        uint64_t Bytes = Size->getFixedValue();
        // The arena itself is only 16-byte aligned, so an over-aligned alloca
        // has no home in it.
        uint64_t Align = AI->getAlign().value();
        if (Align > 16)
          return fail();
        uint64_t Off = alignTo(FrameSize, Align);
        if (Off >= vm::kFrameSize || Off + Bytes > vm::kFrameSize)
          return fail();
        FrameOff[AI] = (uint32_t)Off;
        FrameSize    = (uint32_t)(Off + Bytes);
      }
    return true;
  }

  /// Pre-assign a register to every value-producing instruction.
  ///
  /// This has to happen before emission: a PHI's incoming value can be defined
  /// in a block that comes *later* in layout order (any loop latch), so a
  /// lazily-allocating mapper would hit an unmapped operand and — in the old
  /// code — quietly emit nothing for it.
  bool assignRegs() {
    unsigned Next = 0;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB) {
        if (I.getType()->isVoidTy() || isa<AllocaInst>(&I))
          continue;
        if (!isVMType(I.getType()))
          return fail();
        if (Next >= vm::kNumRegs)
          return fail();
        Reg[&I] = Next++;
      }
    return true;
  }

  // ---- Operand materialisation --------------------------------------------

  unsigned poolIndex(Constant *C) {
    auto It = PoolIdx.find(C);
    if (It != PoolIdx.end())
      return It->second;
    unsigned Idx = Pool.size();
    Pool.push_back(C);
    PoolIdx[C] = Idx;
    return Idx;
  }

  /// Emit code leaving V's canonical 64-bit representation on the stack.
  bool push(Value *V) {
    if (Failed)
      return false;
    if (!isVMType(V->getType()))
      return fail();

    if (auto *CI = dyn_cast<ConstantInt>(V)) {
      E.emitPushImm(CI->getValue().getZExtValue());
      return true;
    }
    if (isa<ConstantPointerNull>(V) || isa<UndefValue>(V)) {
      E.emitPushImm(0);
      return true;
    }
    if (auto *A = dyn_cast<Argument>(V)) {
      auto It = ArgIdx.find(A);
      if (It == ArgIdx.end())
        return fail();
      E.emit8(vm::OP_LOAD_ARG);
      E.emit8((uint8_t)It->second);
      return true;
    }
    if (auto *AI = dyn_cast<AllocaInst>(V)) {
      auto It = FrameOff.find(AI);
      if (It == FrameOff.end())
        return fail();
      E.emit8(vm::OP_PUSH_FRAME);
      E.emit16((uint16_t)It->second);
      return true;
    }
    if (auto *I = dyn_cast<Instruction>(V)) {
      auto It = Reg.find(I);
      if (It == Reg.end())
        return fail();
      E.emit8(vm::OP_PUSH_REG);
      E.emit8((uint8_t)It->second);
      return true;
    }
    // A link-time address: a global, or a constant expression over one. The
    // byte stream cannot hold a relocation, so it goes through the pool.
    if (auto *C = dyn_cast<Constant>(V)) {
      if (!C->getType()->isPointerTy())
        return fail();
      Constant *Entry = ConstantExpr::getPtrToInt(C, Int64Ty);
      unsigned Idx    = poolIndex(Entry);
      if (Idx >= vm::kMaxPoolSize)
        return fail();
      E.emit8(vm::OP_PUSH_POOL);
      E.emit16((uint16_t)Idx);
      return true;
    }
    return fail();
  }

  void popTo(const Instruction *I) {
    auto It = Reg.find(I);
    if (It == Reg.end()) { fail(); return; }
    E.emit8(vm::OP_POP_REG);
    E.emit8((uint8_t)It->second);
  }

  void emitWidthOp(uint8_t Op, unsigned Width) {
    if (Width == 0 || Width > 64) { fail(); return; }
    E.emit8(Op);
    E.emit8((uint8_t)Width);
  }

  // ---- Edges and PHI nodes ------------------------------------------------

  /// Emit the transfer from Pred to Succ: the PHI copies, then the jump.
  ///
  /// The incoming values are all pushed before any register is written, so the
  /// copy is a genuine parallel copy — a pair of PHIs that swap two values
  /// across a loop back-edge lowers correctly without a scratch register.
  bool emitEdge(const BasicBlock *Pred, BasicBlock *Succ) {
    SmallVector<PHINode *, 8> Phis;
    for (PHINode &P : Succ->phis())
      Phis.push_back(&P);
    if (Phis.size() >= vm::kStackSize)
      return fail();
    for (PHINode *P : Phis)
      if (!push(P->getIncomingValueForBlock(Pred)))
        return false;
    for (PHINode *P : reverse(Phis))
      popTo(P);
    BlockPatches.push_back({E.emitJump(vm::OP_JMP), Succ});
    return !Failed;
  }

  // ---- Instruction emission ----------------------------------------------

  bool emitBody() {
    for (BasicBlock &BB : F) {
      BlockOffset[&BB] = E.size();
      for (Instruction &I : BB) {
        if (!emitInst(I))
          return false;
        if (Failed)
          return false;
      }
    }
    return true;
  }

  bool emitInst(Instruction &I) {
    // PHIs are realised by the predecessors, allocas by the frame layout.
    if (isa<PHINode>(&I) || isa<AllocaInst>(&I))
      return true;

    if (auto *BO = dyn_cast<BinaryOperator>(&I))
      return emitBinOp(BO);
    if (auto *CI = dyn_cast<ICmpInst>(&I))
      return emitICmp(CI);
    if (auto *SI = dyn_cast<SelectInst>(&I))
      return emitSelect(SI);
    if (auto *LI = dyn_cast<LoadInst>(&I))
      return emitLoad(LI);
    if (auto *SI = dyn_cast<StoreInst>(&I))
      return emitStore(SI);
    if (auto *CI = dyn_cast<CastInst>(&I))
      return emitCast(CI);
    if (auto *GEP = dyn_cast<GetElementPtrInst>(&I))
      return emitGEP(GEP);
    if (auto *FI = dyn_cast<FreezeInst>(&I))
      return push(FI->getOperand(0)) && (popTo(FI), !Failed);
    if (auto *CI = dyn_cast<CallInst>(&I))
      return emitCall(CI);
    if (auto *RI = dyn_cast<ReturnInst>(&I))
      return emitReturn(RI);
    if (auto *BI = dyn_cast<BranchInst>(&I))
      return emitBranch(BI);
    if (auto *SI = dyn_cast<SwitchInst>(&I))
      return emitSwitch(SI);
    if (isa<UnreachableInst>(&I)) {
      // Control never gets here; returning keeps the block terminated so the
      // interpreter can never run off the end of the blob.
      E.emit8(vm::OP_RET_VOID);
      return true;
    }
    return fail();
  }

  bool emitBinOp(BinaryOperator *BO) {
    uint8_t Op;
    switch (BO->getOpcode()) {
    case Instruction::Add:  Op = vm::OP_ADD;  break;
    case Instruction::Sub:  Op = vm::OP_SUB;  break;
    case Instruction::Mul:  Op = vm::OP_MUL;  break;
    case Instruction::UDiv: Op = vm::OP_UDIV; break;
    case Instruction::SDiv: Op = vm::OP_SDIV; break;
    case Instruction::URem: Op = vm::OP_UREM; break;
    case Instruction::SRem: Op = vm::OP_SREM; break;
    case Instruction::And:  Op = vm::OP_AND;  break;
    case Instruction::Or:   Op = vm::OP_OR;   break;
    case Instruction::Xor:  Op = vm::OP_XOR;  break;
    case Instruction::Shl:  Op = vm::OP_SHL;  break;
    case Instruction::LShr: Op = vm::OP_LSHR; break;
    case Instruction::AShr: Op = vm::OP_ASHR; break;
    default: return fail();
    }
    if (!BO->getType()->isIntegerTy())
      return fail();
    if (!push(BO->getOperand(0)) || !push(BO->getOperand(1)))
      return false;
    emitWidthOp(Op, vmWidth(BO->getType()));
    popTo(BO);
    return !Failed;
  }

  bool emitICmp(ICmpInst *CI) {
    uint8_t Op;
    switch (CI->getPredicate()) {
    case CmpInst::ICMP_EQ:  Op = vm::OP_ICMP_EQ;  break;
    case CmpInst::ICMP_NE:  Op = vm::OP_ICMP_NE;  break;
    case CmpInst::ICMP_ULT: Op = vm::OP_ICMP_ULT; break;
    case CmpInst::ICMP_ULE: Op = vm::OP_ICMP_ULE; break;
    case CmpInst::ICMP_UGT: Op = vm::OP_ICMP_UGT; break;
    case CmpInst::ICMP_UGE: Op = vm::OP_ICMP_UGE; break;
    case CmpInst::ICMP_SLT: Op = vm::OP_ICMP_SLT; break;
    case CmpInst::ICMP_SLE: Op = vm::OP_ICMP_SLE; break;
    case CmpInst::ICMP_SGT: Op = vm::OP_ICMP_SGT; break;
    case CmpInst::ICMP_SGE: Op = vm::OP_ICMP_SGE; break;
    default: return fail();
    }
    Type *OpTy = CI->getOperand(0)->getType();
    if (!isVMType(OpTy) || !CI->getType()->isIntegerTy(1))
      return fail();
    if (!push(CI->getOperand(0)) || !push(CI->getOperand(1)))
      return false;
    emitWidthOp(Op, vmWidth(OpTy));
    popTo(CI);
    return !Failed;
  }

  bool emitSelect(SelectInst *SI) {
    if (!SI->getCondition()->getType()->isIntegerTy(1))
      return fail();
    if (!push(SI->getCondition()) || !push(SI->getTrueValue()) ||
        !push(SI->getFalseValue()))
      return false;
    E.emit8(vm::OP_SELECT);
    popTo(SI);
    return !Failed;
  }

  /// Maps an access size in bytes to its load/store opcode pair.
  static bool accessOpcode(uint64_t Bytes, bool IsStore, uint8_t &Op) {
    switch (Bytes) {
    case 1: Op = IsStore ? vm::OP_STORE8  : vm::OP_LOAD8;  return true;
    case 2: Op = IsStore ? vm::OP_STORE16 : vm::OP_LOAD16; return true;
    case 4: Op = IsStore ? vm::OP_STORE32 : vm::OP_LOAD32; return true;
    case 8: Op = IsStore ? vm::OP_STORE64 : vm::OP_LOAD64; return true;
    default: return false;
    }
  }

  bool emitLoad(LoadInst *LI) {
    if (LI->isAtomic())
      return fail();
    Type *Ty = LI->getType();
    uint8_t Op;
    if (!accessOpcode(DL.getTypeStoreSize(Ty).getFixedValue(), false, Op))
      return fail();
    if (!push(LI->getPointerOperand()))
      return false;
    E.emit8(Op);
    // An iN narrower than its storage (i1 in a byte, say) needs the padding
    // bits cleared to stay canonical.
    unsigned W = vmWidth(Ty);
    if (W != DL.getTypeStoreSizeInBits(Ty).getFixedValue())
      emitWidthOp(vm::OP_TRUNC, W);
    popTo(LI);
    return !Failed;
  }

  bool emitStore(StoreInst *SI) {
    if (SI->isAtomic())
      return fail();
    Value *Val = SI->getValueOperand();
    uint8_t Op;
    if (!accessOpcode(DL.getTypeStoreSize(Val->getType()).getFixedValue(), true,
                      Op))
      return fail();
    // The interpreter pops the value first, so the pointer goes deeper.
    if (!push(SI->getPointerOperand()) || !push(Val))
      return false;
    E.emit8(Op);
    return !Failed;
  }

  bool emitCast(CastInst *CI) {
    Value *Src = CI->getOperand(0);
    Type *SrcTy = Src->getType(), *DstTy = CI->getType();
    if (!isVMType(SrcTy) || !isVMType(DstTy))
      return fail();

    switch (CI->getOpcode()) {
    case Instruction::ZExt:
      // Canonical form is already zero-extended, so this is a copy. The opcode
      // is still emitted: it keeps the bytecode shaped like the source IR.
      if (!push(Src)) return false;
      E.emit8(vm::OP_ZEXT);
      break;
    case Instruction::SExt:
      if (!push(Src)) return false;
      emitWidthOp(vm::OP_SEXT, vmWidth(SrcTy));
      emitWidthOp(vm::OP_TRUNC, vmWidth(DstTy));
      break;
    case Instruction::Trunc:
      if (!push(Src)) return false;
      emitWidthOp(vm::OP_TRUNC, vmWidth(DstTy));
      break;
    case Instruction::PtrToInt:
      if (!push(Src)) return false;
      if (vmWidth(DstTy) != 64)
        emitWidthOp(vm::OP_TRUNC, vmWidth(DstTy));
      break;
    case Instruction::IntToPtr:
      // Narrower sources zero-extend, which canonical form already did.
      if (!push(Src)) return false;
      break;
    case Instruction::BitCast:
      if (SrcTy->isPointerTy() != DstTy->isPointerTy())
        return fail();
      if (!SrcTy->isPointerTy() && vmWidth(SrcTy) != vmWidth(DstTy))
        return fail();
      if (!push(Src)) return false;
      break;
    default:
      return fail();
    }
    popTo(CI);
    return !Failed;
  }

  bool emitGEP(GetElementPtrInst *GEP) {
    if (GEP->getType()->isVectorTy())
      return fail();
    if (!push(GEP->getPointerOperand()))
      return false;

    for (auto GTI = gep_type_begin(GEP), GTE = gep_type_end(GEP); GTI != GTE;
         ++GTI) {
      Value *Idx = GTI.getOperand();
      if (Idx->getType()->isVectorTy())
        return fail();

      if (StructType *STy = GTI.getStructTypeOrNull()) {
        auto *CI = dyn_cast<ConstantInt>(Idx);
        if (!CI)
          return fail();
        uint64_t Off =
            DL.getStructLayout(STy)->getElementOffset(CI->getZExtValue());
        if (Off) {
          E.emitPushImm(Off);
          emitWidthOp(vm::OP_ADD, 64);
        }
        continue;
      }

      TypeSize ElemSize = DL.getTypeAllocSize(GTI.getIndexedType());
      if (ElemSize.isScalable())
        return fail();
      uint64_t Stride = ElemSize.getFixedValue();

      if (auto *CI = dyn_cast<ConstantInt>(Idx)) {
        // GEP indices are signed, so fold with wrapping signed arithmetic.
        uint64_t Off = (uint64_t)CI->getValue().getSExtValue() * Stride;
        if (Off) {
          E.emitPushImm(Off);
          emitWidthOp(vm::OP_ADD, 64);
        }
        continue;
      }

      if (!isVMType(Idx->getType()) || !Idx->getType()->isIntegerTy())
        return fail();
      if (!push(Idx))
        return false;
      if (vmWidth(Idx->getType()) != 64)
        emitWidthOp(vm::OP_SEXT, vmWidth(Idx->getType()));
      if (Stride != 1) {
        E.emitPushImm(Stride);
        emitWidthOp(vm::OP_MUL, 64);
      }
      emitWidthOp(vm::OP_ADD, 64);
    }

    popTo(GEP);
    return !Failed;
  }

  /// Lower llvm.abs / llvm.smax / llvm.smin / llvm.umax / llvm.umin.
  ///
  /// -O2 canonicalises a great many ordinary comparisons into these, so without
  /// them a lot of perfectly virtualisable code is rejected. They need no new
  /// opcodes: a compare plus OP_SELECT is exactly the IR they replaced. Note
  /// push() is free of side effects, so re-pushing an operand is safe.
  bool emitMinMax(CallInst *CI, Intrinsic::ID ID) {
    Type *Ty = CI->getType();
    if (!Ty->isIntegerTy() || Ty->getIntegerBitWidth() > 64)
      return fail();
    unsigned W = vmWidth(Ty);

    if (ID == Intrinsic::abs) {
      Value *A = CI->getArgOperand(0); // arg 1 is the INT_MIN poison flag
      if (!push(A)) return false;      // cond := A <s 0
      E.emitPushImm(0);
      emitWidthOp(vm::OP_ICMP_SLT, W);
      E.emitPushImm(0);                // true value := 0 - A
      if (!push(A)) return false;
      emitWidthOp(vm::OP_SUB, W);
      if (!push(A)) return false;      // false value := A
      E.emit8(vm::OP_SELECT);
      popTo(CI);
      return !Failed;
    }

    uint8_t Cmp;
    switch (ID) {
    case Intrinsic::smax: Cmp = vm::OP_ICMP_SGT; break;
    case Intrinsic::smin: Cmp = vm::OP_ICMP_SLT; break;
    case Intrinsic::umax: Cmp = vm::OP_ICMP_UGT; break;
    case Intrinsic::umin: Cmp = vm::OP_ICMP_ULT; break;
    default: return fail();
    }
    Value *A = CI->getArgOperand(0), *B = CI->getArgOperand(1);
    if (!push(A) || !push(B)) return false; // cond := A cmp B
    emitWidthOp(Cmp, W);
    if (!push(A) || !push(B)) return false; // then A else B
    E.emit8(vm::OP_SELECT);
    popTo(CI);
    return !Failed;
  }

  bool emitCall(CallInst *CI) {
    if (CI->isInlineAsm() || CI->isMustTailCall())
      return fail();
    Function *Callee = CI->getCalledFunction();
    if (!Callee)
      return fail(); // indirect: no relocatable address to pool
    if (Callee->isIntrinsic()) {
      if (isIgnorableIntrinsic(CI))
        return true;
      switch (CI->getIntrinsicID()) {
      case Intrinsic::abs:
      case Intrinsic::smax:
      case Intrinsic::smin:
      case Intrinsic::umax:
      case Intrinsic::umin:
        return emitMinMax(CI, CI->getIntrinsicID());
      default:
        return fail();
      }
    }
    // The interpreter calls through a fixed `uint64_t(uint64_t...)` prototype
    // per arity, so anything whose ABI is not plain C with that many register
    // arguments is off limits — variadic callees, non-C calling conventions,
    // and call sites whose prototype disagrees with the definition.
    if (Callee->isVarArg() || CI->getFunctionType()->isVarArg())
      return fail();
    if (CI->getCallingConv() != CallingConv::C ||
        Callee->getCallingConv() != CallingConv::C)
      return fail();
    if (CI->getFunctionType() != Callee->getFunctionType())
      return fail();
    unsigned N = CI->arg_size();
    if (N > vm::kMaxCallArgs)
      return fail();

    Type *RetTy = CI->getType();
    if (!RetTy->isVoidTy() && !isVMType(RetTy))
      return fail();
    for (unsigned I = 0; I < N; ++I) {
      if (!isVMType(CI->getArgOperand(I)->getType()))
        return fail();
      if (CI->paramHasAttr(I, Attribute::ByVal) ||
          CI->paramHasAttr(I, Attribute::StructRet) ||
          CI->paramHasAttr(I, Attribute::InAlloca) ||
          CI->paramHasAttr(I, Attribute::Preallocated) ||
          CI->paramHasAttr(I, Attribute::SwiftError) ||
          CI->paramHasAttr(I, Attribute::SwiftSelf) ||
          CI->paramHasAttr(I, Attribute::Nest))
        return fail();
    }

    if (!push(Callee))
      return false;
    for (unsigned I = 0; I < N; ++I)
      if (!push(CI->getArgOperand(I)))
        return false;
    E.emit8(vm::OP_CALL);
    E.emit8((uint8_t)N);
    E.emit8(RetTy->isVoidTy() ? 0 : (uint8_t)vmWidth(RetTy));
    if (!RetTy->isVoidTy())
      popTo(CI);
    return !Failed;
  }

  bool emitReturn(ReturnInst *RI) {
    if (Value *V = RI->getReturnValue()) {
      if (!push(V))
        return false;
      E.emit8(vm::OP_RET);
    } else {
      E.emit8(vm::OP_RET_VOID);
    }
    return true;
  }

  bool emitBranch(BranchInst *BI) {
    const BasicBlock *Pred = BI->getParent();
    if (BI->isUnconditional())
      return emitEdge(Pred, BI->getSuccessor(0));

    if (!BI->getCondition()->getType()->isIntegerTy(1))
      return fail();
    if (!push(BI->getCondition()))
      return false;
    // Fall through to the false edge; branch over it to the true edge. The
    // edges carry PHI copies, so they must not be shared.
    uint32_t ToTrue = E.emitJump(vm::OP_JNZ);
    if (!emitEdge(Pred, BI->getSuccessor(1)))
      return false;
    E.patchJump(ToTrue, E.size());
    return emitEdge(Pred, BI->getSuccessor(0));
  }

  bool emitSwitch(SwitchInst *SI) {
    const BasicBlock *Pred = SI->getParent();
    Value *Cond = SI->getCondition();
    if (!Cond->getType()->isIntegerTy() || vmWidth(Cond->getType()) > 64)
      return fail();
    unsigned W = vmWidth(Cond->getType());

    SmallVector<std::pair<uint32_t, BasicBlock *>, 8> Cases;
    for (auto &C : SI->cases()) {
      if (!push(Cond))
        return false;
      E.emitPushImm(C.getCaseValue()->getValue().getZExtValue());
      emitWidthOp(vm::OP_ICMP_EQ, W);
      if (Failed)
        return false;
      Cases.push_back({E.emitJump(vm::OP_JNZ), C.getCaseSuccessor()});
    }
    if (!emitEdge(Pred, SI->getDefaultDest()))
      return false;
    for (auto &[Slot, Dest] : Cases) {
      E.patchJump(Slot, E.size());
      if (!emitEdge(Pred, Dest))
        return false;
    }
    return true;
  }
};

// ── Trampoline construction ─────────────────────────────────────────────────

/// Drop the attributes the original body justified but the trampoline does not.
///
/// `vm_add` is inferred `memory(none) willreturn norecurse`; after
/// virtualisation its body calls into the interpreter, which reads globals, can
/// recurse and — as far as the optimiser can tell — may not return. Leaving the
/// old attributes in place lets later passes fold or delete the call.
static void relaxAttributes(Function &F) {
  F.setMemoryEffects(MemoryEffects::unknown());
  for (Attribute::AttrKind K :
       {Attribute::NoRecurse, Attribute::WillReturn, Attribute::MustProgress,
        Attribute::NoSync, Attribute::NoFree, Attribute::Speculatable,
        Attribute::NoUnwind})
    F.removeFnAttr(K);
  // A `range` return attribute is a promise about the value the *original* body
  // produced; keep the interpreter's result from being folded against it.
  // The attribute was introduced in LLVM 19.
#if LLVM_VERSION_MAJOR >= 19
  F.removeRetAttr(Attribute::Range);
#endif

  for (unsigned I = 0, N = F.arg_size(); I < N; ++I) {
    for (Attribute::AttrKind K :
         {Attribute::ReadNone, Attribute::ReadOnly, Attribute::WriteOnly,
          Attribute::NoFree})
      F.removeParamAttr(I, K);
    // LLVM 21 replaced the `nocapture` attribute with `captures(...)`.
#if LLVM_VERSION_MAJOR >= 21
    F.removeParamAttr(I, Attribute::Captures);
#else
    F.removeParamAttr(I, Attribute::NoCapture);
#endif
  }
}

static void buildTrampoline(Function &F, const VMProgram &P, PRNG &RNG) {
  Module *M        = F.getParent();
  LLVMContext &Ctx = M->getContext();

  auto *Int8Ty  = Type::getInt8Ty(Ctx);
  auto *Int32Ty = Type::getInt32Ty(Ctx);
  auto *Int64Ty = Type::getInt64Ty(Ctx);
  auto *PtrTy   = PointerType::getUnqual(Ctx);

  const uint64_t BCLen = P.BC.size();
  const uint64_t Key   = RNG.next();

  // The interpreter decrypts each byte as it fetches it, so the blob stays
  // constant and read-only. It used to be a mutable global that the trampoline
  // XORed in place on every call, which meant the second call re-encrypted it.
  std::vector<Constant *> EncBytes;
  EncBytes.reserve(BCLen);
  for (uint64_t I = 0; I < BCLen; ++I)
    EncBytes.push_back(ConstantInt::get(
        Int8Ty, P.BC[I] ^ (uint8_t)((Key >> (8 * (I % 8))) & 0xFF)));

  std::string Suffix = std::to_string(RNG.next32());
  auto *BCArrTy      = ArrayType::get(Int8Ty, BCLen);
  auto *BCGlobal =
      new GlobalVariable(*M, BCArrTy, /*isConstant=*/true,
                         GlobalValue::PrivateLinkage,
                         ConstantArray::get(BCArrTy, EncBytes),
                         "kagura_vm_bc_" + Suffix);

  auto *KeyGV = new GlobalVariable(*M, Int64Ty, /*isConstant=*/true,
                                   GlobalValue::PrivateLinkage,
                                   ConstantInt::get(Int64Ty, Key),
                                   "kagura_vm_key_" + Suffix);

  // Addresses the byte stream cannot hold: the linker fills these in.
  Value *PoolPtr = ConstantPointerNull::get(PtrTy);
  if (!P.Pool.empty()) {
    auto *PoolArrTy = ArrayType::get(Int64Ty, P.Pool.size());
    PoolPtr = new GlobalVariable(*M, PoolArrTy, /*isConstant=*/true,
                                 GlobalValue::PrivateLinkage,
                                 ConstantArray::get(PoolArrTy, P.Pool),
                                 "kagura_vm_pool_" + Suffix);
  }

  auto *ExecFTy = FunctionType::get(
      Int64Ty, {PtrTy, Int32Ty, PtrTy, Int32Ty, PtrTy, Int32Ty, Int64Ty},
      false);
  auto *ExecFn = M->getOrInsertFunction("kagura_vm_execute", ExecFTy).getCallee();

  F.deleteBody();
  relaxAttributes(F);
  IRBuilder<> B(BasicBlock::Create(Ctx, "entry", &F));

  const uint32_t NArgs = F.arg_size();
  Value *ArgsPtr       = ConstantPointerNull::get(PtrTy);
  if (NArgs > 0) {
    auto *ArgArrTy = ArrayType::get(Int64Ty, NArgs);
    auto *ArgAlloc = B.CreateAlloca(ArgArrTy, nullptr, "vmargs");
    unsigned Idx   = 0;
    for (Argument &A : F.args()) {
      // Canonical form: integers zero-extend, pointers keep their address.
      Value *V = A.getType()->isPointerTy()
                     ? B.CreatePtrToInt(&A, Int64Ty)
                     : B.CreateZExt(&A, Int64Ty);
      B.CreateStore(V, B.CreateInBoundsGEP(
                           ArgArrTy, ArgAlloc,
                           {ConstantInt::get(Int32Ty, 0),
                            ConstantInt::get(Int32Ty, Idx++)}));
    }
    ArgsPtr = ArgAlloc;
  }

  auto *Result = B.CreateCall(
      ExecFTy, ExecFn,
      {BCGlobal, ConstantInt::get(Int32Ty, BCLen), ArgsPtr,
       ConstantInt::get(Int32Ty, NArgs), PoolPtr,
       ConstantInt::get(Int32Ty, P.Pool.size()),
       B.CreateLoad(Int64Ty, KeyGV, "key")},
      "vm.result");

  Type *RetTy = F.getReturnType();
  if (RetTy->isVoidTy())
    B.CreateRetVoid();
  else if (RetTy->isPointerTy())
    B.CreateRet(B.CreateIntToPtr(Result, RetTy));
  else
    B.CreateRet(B.CreateTrunc(Result, RetTy));
}

} // namespace

// ── LLVM pass ────────────────────────────────────────────────────────────────

PreservedAnalyses VMObfuscationPass::run(Function &F,
                                         FunctionAnalysisManager &) {
  // C.1: The VM interpreter uses platform-specific indirect dispatch and
  // function pointer manipulation that does not lower correctly on Wasm.
  if (kagura::isWasmTarget(*F.getParent()))
    return PreservedAnalyses::all();

  // A naked function's body *is* its ABI, an available_externally body has to
  // stay identical to the one the linker may pick instead, and a personality
  // function means EH the VM cannot model.
  if (F.isDeclaration() || F.hasPersonalityFn() ||
      F.hasFnAttribute(Attribute::Naked) || F.hasAvailableExternallyLinkage())
    return PreservedAnalyses::all();
  if (!shouldObfuscate(F, "vm"))
    return PreservedAnalyses::all();

  auto Program = Lowerer(F).lower();
  if (!Program)
    return PreservedAnalyses::all();

  buildTrampoline(F, *Program, getModulePRNG());
  markObfuscated(F, "vm");
  return PreservedAnalyses::none();
}

} // namespace kagura
