#!/usr/bin/env python3
"""Build the MCP bundle (`unseenkey-<version>.mcpb`) and its registry entry.

The bundle holds `usk` for macOS (universal) and Windows; Claude Desktop runs
`usk mcp --client claude-desktop` from it, and that starts the daemon itself.
Next to the bundle this writes `server.json` for the MCP registry, with the
bundle's release URL and SHA-256.

    build.py --version 0.1.9 --darwin usk-universal --windows usk.exe --out dist
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MCPB_CLI = "@anthropic-ai/mcpb@2.1.2"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--darwin", type=Path, help="universal macOS usk")
    ap.add_argument("--windows", type=Path, help="usk.exe")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    if not (a.darwin or a.windows):
        ap.error("need --darwin, --windows or both")

    out = a.out.resolve()
    stage = out / "mcpb-stage"
    shutil.rmtree(stage, ignore_errors=True)
    (stage / "server").mkdir(parents=True)

    manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    manifest["version"] = a.version
    platforms = []
    if a.darwin:
        dst = stage / "server" / "usk"
        shutil.copyfile(a.darwin, dst)
        dst.chmod(0o755)
        platforms.append("darwin")
    if a.windows:
        shutil.copyfile(a.windows, stage / "server" / "usk.exe")
        platforms.append("win32")
    manifest["compatibility"]["platforms"] = platforms
    (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    shutil.copyfile(ROOT / "apps/desktop/app-icon.png", stage / "icon.png")
    shutil.copyfile(ROOT / "LICENSE-APACHE", stage / "LICENSE")

    bundle = out / f"unseenkey-{a.version}.mcpb"
    npx = shutil.which("npx") or "npx"
    subprocess.run([npx, "--yes", MCPB_CLI, "validate", str(stage / "manifest.json")], check=True)
    subprocess.run([npx, "--yes", MCPB_CLI, "pack", str(stage), str(bundle)], check=True)
    shutil.rmtree(stage)

    sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
    server = json.loads((HERE / "server.json").read_text(encoding="utf-8"))
    server["version"] = a.version
    pkg = server["packages"][0]
    pkg["identifier"] = f"https://github.com/Bhagyesh97/unseenkey/releases/download/v{a.version}/{bundle.name}"
    pkg["fileSha256"] = sha
    (out / "server.json").write_text(json.dumps(server, indent=2) + "\n", encoding="utf-8")
    print(f"{bundle.name} {sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
