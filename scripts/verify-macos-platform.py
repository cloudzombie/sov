#!/usr/bin/env python3
"""Verify the actual ARM64 app, native dependency flags and signed RandomX path.

The Mach-O checks are portable and fixture-tested on every operating system.
Bundle checks use macOS code-signing tools and execute the *signed* executable.
"""

import argparse
import plistlib
import re
import struct
import subprocess
import sys
from pathlib import Path


BASELINE = (11, 0, 0)
ALLOW_JIT = "com.apple.security.cs.allow-jit"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def version_parts(value):
    return tuple(map(int, str(value).split("."))) + (0,) * (3 - len(str(value).split(".")))


def verify_binary(path):
    data = Path(path).read_bytes()
    require(len(data) >= 32, "truncated Mach-O header")
    magic, cpu, subtype, kind, count, commands_size, _, _ = struct.unpack_from("<8I", data)
    require(magic == 0xFEEDFACF, "expected a thin, little-endian 64-bit Mach-O executable")
    require(cpu == 0x0100000C and subtype == 0, "expected baseline arm64, not Intel or arm64e")
    require(kind == 2, "expected a Mach-O executable")
    require(commands_size <= len(data) - 32, "truncated Mach-O load commands")
    end = 32 + commands_size
    offset = 32
    minimums = []
    dependencies = []
    for _ in range(count):
        require(offset + 8 <= end, "truncated Mach-O load command")
        command, size = struct.unpack_from("<2I", data, offset)
        require(size >= 8 and size % 8 == 0 and offset + size <= end, "invalid Mach-O load command size")
        if command == 0x32:  # LC_BUILD_VERSION
            require(size >= 24, "truncated LC_BUILD_VERSION")
            platform, minimum = struct.unpack_from("<2I", data, offset + 8)
            require(platform == 1, "expected macOS, not iOS or another Apple platform")
            minimums.append(((minimum >> 16) & 0xFFFF, (minimum >> 8) & 0xFF, minimum & 0xFF))
        elif command == 0x24:  # LC_VERSION_MIN_MACOSX (older toolchains)
            require(size >= 16, "truncated LC_VERSION_MIN_MACOSX")
            minimum = struct.unpack_from("<I", data, offset + 8)[0]
            minimums.append(((minimum >> 16) & 0xFFFF, (minimum >> 8) & 0xFF, minimum & 0xFF))
        elif command in (0xC, 0x80000018, 0x8000001F, 0x80000023):
            # LC_LOAD_DYLIB, WEAK_DYLIB, REEXPORT_DYLIB, LOAD_UPWARD_DYLIB.
            require(size >= 24, "truncated dynamic library command")
            name_offset = struct.unpack_from("<I", data, offset + 8)[0]
            require(24 <= name_offset < size, "invalid dynamic library name offset")
            name = data[offset + name_offset : offset + size]
            require(b"\0" in name, "unterminated dynamic library name")
            dependency = name.split(b"\0", 1)[0].decode("utf-8")
            require(
                dependency.startswith(("/usr/lib/", "/System/Library/Frameworks/")),
                f"unbundled/non-system dynamic dependency: {dependency}",
            )
            require(".." not in Path(dependency).parts, "invalid system dependency path")
            dependencies.append(dependency)
        offset += size
    require(offset == end, "Mach-O load command count/size disagree")
    require(len(minimums) == 1, "expected exactly one macOS deployment target")
    require(minimums[0] <= BASELINE, f"binary requires macOS {'.'.join(map(str, minimums[0]))}, expected at most 11.0")
    print(f"OK: {path}: baseline arm64, macOS {'.'.join(map(str, minimums[0]))}, {len(dependencies)} system libraries")


def verify_native_flags(build_dir):
    # Inspect what CMake actually compiled, rather than trusting the final Mach-O
    # minimum. Previously cc built RandomX for the host OS while Rust claimed 11.0.
    flag_files = list(Path(build_dir).glob("randomx-rs-*/out/build/CMakeFiles/randomx.dir/flags.make"))
    require(flag_files, f"no RandomX compiler flags found under {build_dir}")
    for path in flag_files:
        lines = [line for line in path.read_text().splitlines() if re.match(r"C(?:XX)?_FLAGS(?:arm64)? =", line)]
        require(lines, f"no C/C++ compiler flags in {path}")
        for line in lines:
            require("-march=native" not in line and "-mcpu=" not in line, f"host-specific native CPU flags in {path}")
            architectures = re.findall(r"-march=([^ ]+)", line)
            require(architectures and all(value == "armv8-a+crypto" for value in architectures), f"RandomX must use portable ARMv8 crypto baseline in {path}")
            minimums = re.findall(r"-mmacosx-version-min=([0-9.]+)", line)
            require(minimums and all(version_parts(v) <= BASELINE for v in minimums), f"RandomX C/C++ deployment target exceeds 11.0 in {path}: {line}")
        print(f"OK: {path}: RandomX ARMv8 baseline and macOS <=11.0")


def run_checked(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=90)


def verify_bundle(app):
    require(sys.platform == "darwin", "signed bundle verification requires macOS")
    app = Path(app)
    contents = app / "Contents"
    info = plistlib.loads((contents / "Info.plist").read_bytes())
    require(info.get("CFBundleExecutable") == "sov-station", "unexpected bundle executable")
    require(version_parts(info.get("LSMinimumSystemVersion", "999")) == BASELINE, "Info.plist must declare macOS 11.0")
    binary = contents / "MacOS" / "sov-station"
    verify_binary(binary)
    run_checked("codesign", "--verify", "--strict", "--verbose=2", str(binary))
    run_checked("codesign", "--verify", "--strict", "--verbose=2", str(app))
    details = run_checked("codesign", "--display", "--verbose=4", str(app)).stderr
    require("runtime" in details, "bundle signature must enable Hardened Runtime")
    require("Info.plist=not bound" not in details, "signature does not bind Info.plist")
    require("Sealed Resources=none" not in details, "bundle resources are not sealed")
    entitlements = run_checked("codesign", "--display", "--entitlements", ":-", str(binary)).stdout
    parsed = plistlib.loads(entitlements.encode()) if entitlements.strip() else {}
    require(parsed == {ALLOW_JIT: True}, "signed app must carry only the RandomX allow-jit runtime exception")
    result = run_checked(str(binary.resolve()), "--self-test-platform")
    require("platform self-test: RandomX known answers passed" in result.stdout, "signed app did not report a passing RandomX self-test")
    require("(backend: JIT)" in result.stdout, "signed ARM64 app did not exercise RandomX JIT")
    print(result.stdout.strip())
    print(f"OK: {app}: bound bundle signature, Hardened Runtime and signed RandomX/JIT self-test")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("binary", "native", "bundle"))
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        {"binary": verify_binary, "native": verify_native_flags, "bundle": verify_bundle}[args.mode](args.path)
    except (ValueError, OSError, UnicodeError, struct.error, plistlib.InvalidFileException, subprocess.SubprocessError) as error:
        print(f"MACOS PLATFORM CHECK FAILED: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stdout or "", error.stderr or "", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
