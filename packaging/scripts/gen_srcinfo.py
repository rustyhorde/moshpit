#!/usr/bin/env python3
"""
Generate minimal .SRCINFO files from the existing PKGBUILDs.

Usage:
    python3 packaging/scripts/gen_srcinfo.py --pkgver 0.2.0 --sha256 <hex>

The script reads each PKGBUILD in packaging/arch/<pkg>/ and emits a
.SRCINFO file next to it. Only the fields that AUR requires are written:
pkgbase, pkgver, pkgrel, pkgdesc, url, arch, license, depends, makedepends,
source, sha256sums, and pkgname.

NOTE: This intentionally avoids needing makepkg (which is not available on
Ubuntu runners). For local validation, run `makepkg --printsrcinfo` on an
Arch Linux machine or in an Arch container and compare.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def extract(text: str, key: str) -> str:
    """Return the unquoted value of a simple key=value line."""
    m = re.search(rf"^{key}=['\"]?([^'\"]+)['\"]?", text, re.MULTILINE)
    return m.group(1).strip() if m else ""


def extract_array(text: str, key: str) -> list[str]:
    """Return all values from a bash array assignment: key=('a' 'b' ...)."""
    m = re.search(rf"^{key}=\(([^)]*)\)", text, re.MULTILINE | re.DOTALL)
    if not m:
        return []
    inner = m.group(1)
    return [v.strip("'\"") for v in re.findall(r"['\"]([^'\"]+)['\"]", inner)]


def gen_srcinfo(pkgbuild_path: Path, pkgver: str, sha256: str) -> str:
    text = pkgbuild_path.read_text()

    pkgname    = extract(text, "pkgname")
    pkgrel     = extract(text, "pkgrel")
    pkgdesc    = extract(text, "pkgdesc")
    url        = extract(text, "url")
    arches     = extract_array(text, "arch")
    licenses   = extract_array(text, "license")
    depends    = extract_array(text, "depends")
    makedepends = extract_array(text, "makedepends")
    sources    = extract_array(text, "source")
    sha256sums = extract_array(text, "sha256sums")

    # Replace the placeholder pkgver in source URLs
    sources = [s.replace("$pkgver", pkgver).replace("${pkgver}", pkgver)
               .replace("$pkgname", pkgname).replace("${pkgname}", pkgname)
               for s in sources]

    # Replace the first SKIP with the real sha256
    sha256sums_out = []
    replaced = False
    for s in sha256sums:
        if s == "SKIP" and not replaced:
            sha256sums_out.append(sha256)
            replaced = True
        else:
            sha256sums_out.append(s)

    lines: list[str] = []
    lines.append(f"pkgbase = {pkgname}")
    lines.append(f"\tpkgdesc = {pkgdesc}")
    lines.append(f"\tpkgver = {pkgver}")
    lines.append(f"\tpkgrel = {pkgrel}")
    lines.append(f"\turl = {url}")
    for a in arches:
        lines.append(f"\tarch = {a}")
    for lic in licenses:
        lines.append(f"\tlicense = {lic}")
    for md in makedepends:
        lines.append(f"\tmakedepends = {md}")
    for src in sources:
        lines.append(f"\tsource = {src}")
    for sha in sha256sums_out:
        lines.append(f"\tsha256sums = {sha}")
    lines.append("")
    lines.append(f"pkgname = {pkgname}")
    for dep in depends:
        lines.append(f"\tdepends = {dep}")
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pkgver", required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent.parent
    arch_dir = repo_root / "packaging" / "arch"

    packages = [
        "moshpit-keygen", "moshpit", "moshpits",
        "moshpit-agent", "moshpit-agent-fido2", "moshpit-agent-systemd-creds",
        "moshpit-agent-ssh-agent-piggyback", "moshpit-agent-secret-service",
        "moshpit-agent-tpm", "moshpit-agent-fprintd", "moshpit-agent-full",
    ]
    for pkg in packages:
        pkgbuild = arch_dir / pkg / "PKGBUILD"
        if not pkgbuild.exists():
            print(f"[WARN] {pkgbuild} not found, skipping", file=sys.stderr)
            continue
        srcinfo_text = gen_srcinfo(pkgbuild, args.pkgver, args.sha256)
        out = arch_dir / pkg / ".SRCINFO"
        out.write_text(srcinfo_text)
        print(f"[OK] wrote {out.relative_to(repo_root)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
