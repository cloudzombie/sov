#!/usr/bin/env python3
"""Negative fixtures for the Apple Silicon shipping guards; no Mac required."""

import contextlib
import importlib.util
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("macos_platform", Path(__file__).resolve().parents[1] / "verify-macos-platform.py")
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)


def macho(cpu=0x0100000C, subtype=0, minimum=0x0B0000, os_platform=1, library="/usr/lib/libSystem.B.dylib", deployment=True):
    commands = []
    if deployment:
        commands.append(struct.pack("<6I", 0x32, 24, os_platform, minimum, 0x1A0000, 0))
    name = library.encode() + b"\0"
    size = (24 + len(name) + 7) & ~7
    commands.append(struct.pack("<6I", 0xC, size, 24, 0, 0, 0) + name + b"\0" * (size - 24 - len(name)))
    body = b"".join(commands)
    return struct.pack("<8I", 0xFEEDFACF, cpu, subtype, 2, len(commands), len(body), 0, 0) + body


class Guards(unittest.TestCase):
    def check_binary(self, data, error=None):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "sov-station"
            binary.write_bytes(data)
            with contextlib.redirect_stdout(io.StringIO()):
                if error:
                    with self.assertRaisesRegex(ValueError, error):
                        platform.verify_binary(binary)
                else:
                    platform.verify_binary(binary)

    def test_baseline_arm64(self):
        self.check_binary(macho())

    def test_intel_and_arm64e_are_rejected(self):
        self.check_binary(macho(cpu=0x01000007), "baseline arm64")
        self.check_binary(macho(subtype=2), "baseline arm64")

    def test_host_os_minimum_drift_is_rejected(self):
        self.check_binary(macho(minimum=0x1A0500), "requires macOS 26.5")

    def test_missing_or_wrong_platform_is_rejected(self):
        self.check_binary(macho(deployment=False), "exactly one")
        self.check_binary(macho(os_platform=2), "expected macOS")

    def test_homebrew_and_relative_dependencies_are_rejected(self):
        for library in ("/opt/homebrew/lib/libc++.dylib", "@rpath/librandomx.dylib", "/usr/lib/../../tmp/evil.dylib"):
            self.check_binary(macho(library=library), "dependency")

    def test_truncation_is_rejected(self):
        self.check_binary(macho()[:20], "truncated")
        self.check_binary(macho()[:-1], "truncated")

    def test_corrupt_load_commands_are_rejected(self):
        data = bytearray(macho())
        struct.pack_into("<I", data, 36, 4)
        self.check_binary(data, "load command size")

    def test_cpp_host_minimum_and_native_cpu_flags_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "randomx-rs-example/out/build/CMakeFiles/randomx.dir/flags.make"
            path.parent.mkdir(parents=True)
            for flags, error in (
                ("-march=armv8-a+crypto -mmacosx-version-min=26.5", "deployment target"),
                ("-march=native -mmacosx-version-min=11.0", "host-specific"),
                ("-mcpu=apple-m4 -march=armv8-a+crypto -mmacosx-version-min=11.0", "host-specific"),
                ("-march=armv8-a+crypto -march=armv9.2-a -mmacosx-version-min=11.0", "portable ARMv8"),
            ):
                path.write_text(f"C_FLAGS = {flags}\nCXX_FLAGS = {flags}\n")
                with self.assertRaisesRegex(ValueError, error):
                    platform.verify_native_flags(directory)
            path.write_text("C_FLAGS = -march=armv8-a+crypto -mmacosx-version-min=11.0\nCXX_FLAGS = -march=armv8-a+crypto -mmacosx-version-min=11.0\n")
            with contextlib.redirect_stdout(io.StringIO()):
                platform.verify_native_flags(directory)


if __name__ == "__main__":
    unittest.main()
