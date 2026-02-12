#!/usr/bin/env python3
"""
Merge multiple kernel configs into one, with optional dedup.

Usage:
  merge_full_configs.py [options] CONFIG [CONFIG ...]

  CONFIG: full .config files to merge (first is base, later ones override/add).
  -d/--dedup: fragment file; any CONFIG_ present here is omitted from output
              (so merge with this fragment later without duplication).
  -o/--output: output path (default: arch/arm64/configs/full.config).

Environment-related configs (CC_VERSION, LOCALVERSION, etc.) are always excluded.

Example:
  scripts/kconfig/merge_full_configs.py -d arch/arm64/configs/nvidia.config -o arch/arm64/configs/full.config \\
    patches/config_compare/nvidia-6.17/config-6.17.0-1008-nvidia \\
    patches/config_compare/generic-6.18/config-6.18.0-9-generic
"""
import argparse
import re
import sys
from pathlib import Path

# Pre-compiled regexes for config parsing (used in hot loops)
RE_NOTSET = re.compile(r'^# CONFIG_([A-Za-z0-9_]+) is not set\s*$')
RE_SET = re.compile(r'^(CONFIG_([A-Za-z0-9_]+)=(.*))$')

# CONFIG_ name prefixes to exclude (environment / toolchain)
ENV_PREFIXES = (
    "CC_VERSION", "GCC_VERSION", "RUSTC_VERSION", "RUSTC_LLVM", "RUST_IS_AVAILABLE",
    "CC_CAN_LINK", "VERSION_SIGNATURE", "LOCALVERSION", "LOCALVERSION_AUTO", "BUILD_SALT",
    "CC_HAS_", "CC_HAVE_", "CC_IS_", "CC_NO_", "CC_IMPLICIT_",
    "GCC_NO_", "GCC_SUPPORTS_", "RUSTC_SUPPORTS_", "CC_OPTIMIZE_",
    "AS_VERSION", "AS_IS_", "LD_VERSION", "LD_IS_", "LLD_VERSION", "CLANG_VERSION",
    "PAHOLE_VERSION", "LD_CAN_USE_",
)


def is_env_key(name: str) -> bool:
    return any(name == p or name.startswith(p) for p in ENV_PREFIXES)


def parse_full_config(path: Path):
    """Parse full .config: CONFIG_X=val or # CONFIG_X is not set. Returns ordered (key, line)."""
    entries = []
    for line in open(path, encoding="utf-8", errors="replace"):
        s = line.rstrip("\r\n")
        if not s.strip():
            entries.append((None, s))
            continue
        m = RE_NOTSET.match(s.strip())
        if m:
            entries.append((m.group(1), s))
            continue
        m = RE_SET.match(s)
        if m:
            entries.append((m.group(2), s))
            continue
        if s.strip().startswith("#"):
            entries.append((None, s))
            continue
        entries.append((None, s))
    return entries


def full_config_to_dict(path: Path):
    """Parse full .config into key -> line (only CONFIG_ lines)."""
    d = {}
    for key, line in parse_full_config(path):
        if key is not None:
            d[key] = line
    return d


def fragment_keys(path: Path):
    """Set of CONFIG_ keys defined in a fragment (for dedup)."""
    keys = set()
    for line in open(path, encoding="utf-8", errors="replace"):
        s = line.strip()
        if not s or (s.startswith("#") and " is not set" not in s):
            continue
        m = RE_NOTSET.match(s)
        if m:
            keys.add(m.group(1))
            continue
        m = RE_SET.match(s)
        if m:
            keys.add(m.group(2))
    return keys


def main():
    repo = Path(__file__).resolve().parents[2]
    default_out = repo / "arch/arm64/configs/full.config"

    ap = argparse.ArgumentParser(
        description="Merge kernel configs with optional dedup.",
        epilog="Example: %(prog)s -d arch/arm64/configs/nvidia.config -o arch/arm64/configs/full.config nvidia-6.17/config generic-6.18/config",
    )
    ap.add_argument(
        "configs",
        nargs="+",
        type=Path,
        help="Config files to merge (first is base, later override/add).",
    )
    ap.add_argument(
        "-d", "--dedup",
        type=Path,
        metavar="FILE",
        help="Fragment to dedup against: omit from output any CONFIG_ present in FILE.",
    )
    ap.add_argument(
        "-o", "--output",
        type=Path,
        default=default_out,
        metavar="FILE",
        help=f"Output path (default: {default_out}).",
    )
    args = ap.parse_args()

    # Resolve paths relative to repo
    config_paths = [c if c.is_absolute() else repo / c for c in args.configs]
    for p in config_paths:
        if not p.exists():
            print(f"Error: config not found: {p}", file=sys.stderr)
            sys.exit(1)

    dedup_keys = set()
    if args.dedup is not None:
        dedup_path = args.dedup if args.dedup.is_absolute() else repo / args.dedup
        if not dedup_path.exists():
            print(f"Error: dedup file not found: {dedup_path}", file=sys.stderr)
            sys.exit(1)
        dedup_keys = fragment_keys(dedup_path)
        print(f"Dedup fragment has {len(dedup_keys)} CONFIG options", file=sys.stderr)

    # Merge: first config is base (order + values), then each overlay overwrites/adds
    merged = {}  # key -> line
    base_entries = parse_full_config(config_paths[0])
    base_order = [k for k, _ in base_entries if k is not None and not is_env_key(k)]

    for key in base_order:
        merged[key] = None  # placeholder to preserve order

    for cfg_path in config_paths:
        d = full_config_to_dict(cfg_path)
        for key, line in d.items():
            if is_env_key(key):
                continue
            merged[key] = line

    overlay_only = sorted(k for k in merged if k not in base_order)
    ordered_keys = list(base_order) + overlay_only  # for stats

    # Build output: preserve comments/blanks from base, output CONFIG lines (merged value, skip dedup/env)
    header = [
        "# Merged config (env excluded).",
        "# Inputs: " + ", ".join(p.name for p in config_paths) + ".",
    ]
    if args.dedup is not None:
        dedup_path = args.dedup if args.dedup.is_absolute() else repo / args.dedup
        header.append("# Dedup: " + dedup_path.name + ".")
    header.extend(["#", ""])
    out_lines = list(header)
    seen = set()
    for key, line in base_entries:
        if key is None:
            # Comment or blank line from base config
            out_lines.append(line)
            continue
        if is_env_key(key) or key in dedup_keys:
            continue
        merged_line = merged.get(key)
        if merged_line is not None:
            out_lines.append(merged_line)
            seen.add(key)
    # Append options only in overlay configs (no section comments in base)
    if overlay_only:
        to_append = [k for k in overlay_only if k not in dedup_keys and not is_env_key(k)]
        if to_append:
            out_lines.append("")
            out_lines.append("#")
            out_lines.append("# Additional options (from overlay configs)")
            out_lines.append("#")
            out_lines.append("")
            for key in to_append:
                out_lines.append(merged[key])
                seen.add(key)

    out_path = args.output if args.output.is_absolute() else repo / args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))
        if out_lines and not out_lines[-1].endswith("\n"):
            f.write("\n")

    removed_dedup = sum(1 for k in ordered_keys if k in dedup_keys)
    print(f"Wrote {out_path}", file=sys.stderr)
    print(f"  CONFIG lines in output: {len(seen)}", file=sys.stderr)
    if dedup_keys:
        print(f"  Omitted (in dedup fragment): {removed_dedup}", file=sys.stderr)


if __name__ == "__main__":
    main()
