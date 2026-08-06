//===-- Passes.h - Every Kagura pass declaration ---------------------------===//
//
// Umbrella header. The declarations live in Passes/<Category>.h, one per
// lib/Transforms/ subdirectory, so a pass declaration sits in the same
// category as its implementation.
//
// Plugin.cpp and the fuzz targets want all of them, so they include this.
// A pass source should include only its own category header — that is what
// keeps a new declaration from quietly acquiring users in three other
// categories.
//
// This used to be one 400-line file whose section comments had drifted out of
// step with the directory layout: Substitution and CSEBreak were filed under
// "Control Flow" while their sources live in Data/, and VTableProtection under
// "RTTI / vtable protection" while its source lived in CFG/.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "kagura/Passes/ABI.h"
#include "kagura/Passes/AntiAnalysis.h"
#include "kagura/Passes/CFG.h"
#include "kagura/Passes/Data.h"
#include "kagura/Passes/Infrastructure.h"
#include "kagura/Passes/Platform.h"
#include "kagura/Passes/VM.h"
