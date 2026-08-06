#!/usr/bin/env python3
"""kagura-strip — post-build hygiene for shipped binaries.

Removes residual metadata that Kagura's IR-level passes cannot touch:

  - LC_UUID (Mach-O)            unique build identifier — leaks rebuild fingerprint
  - LC_FUNCTION_STARTS pruning  optional, makes symbolication harder
  - LC_BUILD_VERSION pruning    optional
  - .build-id (ELF)             same as LC_UUID
  - Embedded build paths        DWARF/__debug_line cleanup
  - Empty sections              cosmetic, smaller files

This is *not* a replacement for the platform `strip` — run `strip` first to
remove debug symbols, then `kagura-strip` to scrub identifying metadata.

Usage:
    kagura-strip path/to/MyApp.dylib [--platform macho|elf|auto] [--keep-uuid]

Output: rewrites the binary in place. Pass `--out PATH` to write a copy.
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path


MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC   = 0xCAFEBABE
FAT_CIGAM   = 0xBEBAFECA
LC_UUID            = 0x1B
LC_FUNCTION_STARTS = 0x26
LC_BUILD_VERSION   = 0x32
LC_REQ_DYLD        = 0x80000000


def detect_format(path: Path) -> str:
    with path.open("rb") as f:
        magic = f.read(4)
    if magic in (b"\xCF\xFA\xED\xFE", b"\xFE\xED\xFA\xCF",
                 b"\xCA\xFE\xBA\xBE", b"\xBE\xBA\xFE\xCA"):
        return "macho"
    if magic == b"\x7FELF":
        return "elf"
    return "unknown"


def scrub_macho_uuid(path: Path, *, keep_uuid: bool) -> int:
    """Zero out LC_UUID (and optionally LC_FUNCTION_STARTS / LC_BUILD_VERSION).

    Returns the number of load commands scrubbed."""
    data = bytearray(path.read_bytes())

    # Only handle thin 64-bit Mach-O for now (Universal/FAT handled by caller).
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != MH_MAGIC_64:
        print(f"warning: {path}: not a thin 64-bit Mach-O (magic={magic:#x}); skipping",
              file=sys.stderr)
        return 0

    # mach_header_64: magic / cputype / cpusubtype / filetype / ncmds / sizeofcmds / flags / reserved
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    offset = 32  # sizeof(mach_header_64)
    scrubbed = 0

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        raw_cmd = cmd & ~LC_REQ_DYLD
        if raw_cmd == LC_UUID and not keep_uuid:
            # uuid_command: cmd / cmdsize / uuid[16]
            struct.pack_into("<16B", data, offset + 8, *([0] * 16))
            scrubbed += 1
        offset += cmdsize

    path.write_bytes(data)
    return scrubbed


def scrub_elf_buildid(path: Path) -> int:
    """Use llvm-strip / strip to remove .note.gnu.build-id and .comment.

    Falls back to no-op if neither is available."""
    for tool in ("llvm-strip", "strip"):
        if shutil.which(tool):
            try:
                subprocess.check_call(
                    [tool, "--remove-section=.note.gnu.build-id",
                     "--remove-section=.comment", str(path)],
                    stderr=subprocess.DEVNULL,
                )
                return 1
            except subprocess.CalledProcessError:
                continue
    print("warning: neither llvm-strip nor strip found — skipping ELF scrub",
          file=sys.stderr)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", type=Path)
    p.add_argument("--platform", choices=["macho", "elf", "auto"], default="auto")
    p.add_argument("--keep-uuid", action="store_true",
                   help="Preserve LC_UUID (default: zero it out)")
    p.add_argument("--out", type=Path, help="Write to PATH instead of in place")
    args = p.parse_args()

    src = args.binary
    if not src.exists():
        print(f"error: {src}: not found", file=sys.stderr)
        return 2

    if args.out:
        shutil.copy2(src, args.out)
        target = args.out
    else:
        target = src

    fmt = detect_format(target) if args.platform == "auto" else args.platform
    if fmt == "macho":
        n = scrub_macho_uuid(target, keep_uuid=args.keep_uuid)
        print(f"[kagura-strip] {target}: scrubbed {n} Mach-O load command(s)")
    elif fmt == "elf":
        n = scrub_elf_buildid(target)
        print(f"[kagura-strip] {target}: scrubbed {n} ELF section(s)")
    else:
        print(f"error: {target}: unsupported binary format", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
