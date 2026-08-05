"""Provision QEMU kernel assets + boot templates on the analysis VM.

This is the *only* sanctioned way to obtain kernels: it reads the registry in
``iot_agent.tools.kernel_assets`` (copy from FirmAE binaries first, pinned
download second) and writes/updates ``manifest.json`` on the VM.

Usage (from Windows; requires VM config in .env):

    python scripts/provision_kernels.py --arch mipsel
    python scripts/provision_kernels.py --all
    python scripts/provision_kernels.py --arch mipsel --dry-run

Local mode (testing, or FirmAE mounted on the same host):

    python scripts/provision_kernels.py --local /opt/firmae/binaries /data/qemu-images/kernels
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from iot_agent.tools import kernel_assets
from iot_agent.tools.kernel_assets import ARCH_KERNELS
from iot_agent.tools.remote_vm import VMRemoteExecutor


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--arch", action="append", help="architecture(s) to provision")
    p.add_argument("--all", action="store_true", help="provision all registered archs")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="print the VM commands without executing them",
    )
    p.add_argument(
        "--local",
        nargs=2,
        metavar=("FIRMAE_BINARIES_DIR", "KERNELS_DIR"),
        help="provision from a local FirmAE binaries dir (no SSH)",
    )
    p.add_argument(
        "--templates-dir",
        default=None,
        help="local images dir for boot-templates.json (only with --local)",
    )
    p.add_argument(
        "--runtime",
        action="store_true",
        help="provision FirmAE runtime binaries (busybox/libnvram/console)",
    )
    return p.parse_args()


def _selected_archs(args: argparse.Namespace) -> list[str]:
    if args.arch:
        archs = [a.strip().lower() for a in args.arch]
    elif args.all:
        archs = list(ARCH_KERNELS)
    else:
        archs = list(ARCH_KERNELS)
    unknown = [a for a in archs if a not in ARCH_KERNELS]
    if unknown:
        print(f"unknown archs: {unknown}; registered: {list(ARCH_KERNELS)}")
        sys.exit(2)
    return archs


async def _provision_vm(args: argparse.Namespace) -> int:
    if args.runtime:
        if args.dry_run:
            summary = await kernel_assets.provision_runtime_assets(None, dry_run=True)
            print("runtime assets to download:", summary["downloaded"])
            return 0
        async with VMRemoteExecutor() as vm:
            summary = await kernel_assets.provision_runtime_assets(vm)
        print(f"downloaded: {len(summary['downloaded'])} "
              f"skipped: {len(summary['skipped'])} "
              f"failed: {summary['failed']}")
        return 1 if summary["failed"] else 0

    archs = _selected_archs(args)
    if args.dry_run:
        print("=== FirmAE copy scripts (dry run) ===")
        for a in archs:
            print(f"--- {a} ---")
            print(kernel_assets._firmae_copy_script(a))
            print()
        print("=== download scripts (dry run) ===")
        for a in archs:
            print(f"--- {a} ---")
            print(kernel_assets._download_script(a))
            print()
        print("=== boot templates ===")
        print(kernel_assets.DEFAULT_BOOT_TEMPLATES)
        return 0

    async with VMRemoteExecutor() as vm:
        if not vm.configured:
            print("VM not configured; check IOT_AGENT_VM_SSH_* in .env")
            return 1
        await kernel_assets.ensure_boot_templates(vm)
        for a in archs:
            path = await kernel_assets.ensure_kernel(vm, a)
            if path:
                print(f"[ok] {a}: {path}")
            else:
                print(f"[fail] {a}: could not provision kernel")
                return 1
        print("manifest:", kernel_assets.manifest_path())
    return 0


def _provision_local(args: argparse.Namespace) -> int:
    if args.runtime:
        print("--runtime does not support --local; run on the VM instead")
        return 2
    firmae_dir, kernels = args.local
    archs = _selected_archs(args)
    if not archs:
        archs = None
    summary = kernel_assets.provision_local(firmae_dir, kernels, arch=archs)
    for item in summary["copied"]:
        print(f"[ok] {item['arch']}: {item['path']} sha256={item['sha256'][:16]}...")
    if summary["missing"]:
        print(f"[skip] no FirmAE kernel found for: {summary['missing']}")
    if args.templates_dir:
        out = kernel_assets.write_boot_templates_local(args.templates_dir)
        print("[ok] boot templates:", out)
    return 0


def main() -> int:
    args = _parse_args()
    if args.local:
        return _provision_local(args)
    return asyncio.run(_provision_vm(args))


if __name__ == "__main__":
    sys.exit(main())
