#!/usr/bin/env python3

#find byte sequences that appear in ALL G1 files but are ABSENT from all G2 files.
#for APK/ZIP/JAR/XAPK files, automatically extracts inner files and searches those instead

import argparse
import io
import json
import os
import sys
import zipfile
from pathlib import Path

# APK/ZIP extraction

# extensions to extract from APK/ZIP archives
_EXTRACT_EXTS = {
    ".dex", ".so", ".jar", ".xml", ".json", ".bin",
    ".proto", ".class", ".js", ".html", ".db",
}
# extensions to skip
_SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4",
    ".ogg", ".wav", ".ttf", ".otf", ".woff",
}

def load_file_data(path: str, unzip: bool = True) -> dict:
    #Returns {logical_name: bytes} for a file
    suffix = Path(path).suffix.lower()
    if unzip and suffix in (".apk", ".xapk", ".zip", ".jar", ".aab"):
        try:
            result = {}
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    name = info.filename
                    ext  = Path(name).suffix.lower()
                    if ext in _SKIP_EXTS:
                        continue
                    if _EXTRACT_EXTS and ext not in _EXTRACT_EXTS and ext != "":
                        # Include unknown extensions too — better safe
                        pass
                    try:
                        data = zf.read(name)
                        if data:
                            result[f"{path}!{name}"] = data
                    except Exception:
                        pass
            if result:
                return result
        except zipfile.BadZipFile:
            pass
    # fallback: raw bytes
    with open(path, "rb") as f:
        return {path: f.read()}


#fast n-gram hashing using memoryview + built-in hash()

def ngram_hash_set(data: bytes, length: int, step: int) -> set:
    mv = memoryview(data)
    n  = len(data)
    if n < length:
        return set()
    return {hash(mv[i: i + length]) for i in range(0, n - length + 1, step)}


def ngram_hash_set_with_map(data: bytes, length: int, step: int):
    mv  = memoryview(data)
    n   = len(data)
    if n < length:
        return set(), {}
    hashes = set()
    h2b    = {}
    for i in range(0, n - length + 1, step):
        sl = mv[i: i + length]
        h  = hash(sl)
        hashes.add(h)
        if h not in h2b:
            h2b[h] = bytes(sl)
    return hashes, h2b


# per-file: union of hashes across all inner files

def file_hashes(path: str, length: int, step: int,
                unzip: bool, collect_bytes: bool = False):
    parts = load_file_data(path, unzip)
    all_hashes = set()
    all_h2b    = {}
    for _, data in parts.items():
        if collect_bytes:
            h, h2b = ngram_hash_set_with_map(data, length, step)
            all_hashes |= h
            all_h2b.update({k: v for k, v in h2b.items() if k not in all_h2b})
        else:
            all_hashes |= ngram_hash_set(data, length, step)
    return (all_hashes, all_h2b) if collect_bytes else (all_hashes, {})

#per-length search
def find_at_length(g1_paths, g2_paths, length, step, unzip, verbose):
    if verbose:
        print(f"  [len={length:2d}]", end=" ", flush=True)

    # first G1: collect hashes + bytes mapping
    g1_common, h2b = file_hashes(g1_paths[0], length, step, unzip,
                                  collect_bytes=True)
    if not g1_common:
        if verbose: print("0 in G1[0] — skip")
        return []

    # remaining G1: intersect
    for path in g1_paths[1:]:
        h, _ = file_hashes(path, length, step, unzip)
        g1_common &= h
        if not g1_common:
            break

    if not g1_common:
        if verbose: print("0 common — skip")
        return []

    if verbose:
        print(f"{len(g1_common):,} G1-common →", end=" ", flush=True)

    # G2: subtract
    for path in g2_paths:
        h, _ = file_hashes(path, length, step, unzip)
        g1_common -= h
        if not g1_common:
            break

    if not g1_common:
        if verbose: print("0 survive G2")
        return []

    if verbose:
        print(f"{len(g1_common):,} survive G2", flush=True)

    results = []
    for h in g1_common:
        seq = h2b.get(h)
        if seq is None:
            continue
        try:
            ascii_repr = seq.decode("ascii")
            ascii_repr = ascii_repr if ascii_repr.isprintable() else None
        except Exception:
            ascii_repr = None
        results.append({"hex": seq.hex(), "length": length,
                        "g1_coverage": 1.0, "g2_hits": 0, "ascii": ascii_repr})
    return results


# deduplication

def deduplicate(results, verbose):
    if not results:
        return results
    if verbose:
        print(f"[*] Deduplicating {len(results):,} sequences...", end=" ", flush=True)
    results.sort(key=lambda x: x["length"], reverse=True)
    maximal, maximal_bytes = [], []
    for r in results:
        seq = bytes.fromhex(r["hex"])
        if not any(seq in m for m in maximal_bytes):
            maximal.append(r)
            maximal_bytes.append(seq)
    if verbose:
        print(f"{len(maximal):,} maximal remain")
    return maximal


# Public API
def find_distinctive(g1_paths, g2_paths, min_len=8, max_len=32,
                     step=4, unzip=True, verbose=True):
    if not g1_paths:
        raise ValueError("G1 must contain at least one file.")
    if verbose:
        print(f"[*] G1={len(g1_paths)}, G2={len(g2_paths)}, "
              f"lengths {min_len}–{max_len}, step={step}, unzip={unzip}")
        for p in g1_paths:
            sz = os.path.getsize(p)
            print(f"    G1  {sz:>12,} B  {p}")
        for p in g2_paths:
            sz = os.path.getsize(p)
            print(f"    G2  {sz:>12,} B  {p}")

    all_results = []
    for length in range(min_len, max_len + 1):
        all_results.extend(
            find_at_length(g1_paths, g2_paths, length, step, unzip, verbose))

    all_results = deduplicate(all_results, verbose)
    all_results.sort(key=lambda x: x["length"], reverse=True)
    return all_results


# YARA

def to_yara(results, rule_name="distinctive_g1"):
    if not results:
        return "// No distinctive sequences found."
    lines = [
        f'rule {rule_name} {{',
        '    meta:',
        '        description = "Auto-generated by distinctive_bytes.py"',
        '    strings:',
    ]
    for i, r in enumerate(results[:20]):
        hs = " ".join(r["hex"][j:j+2] for j in range(0, len(r["hex"]), 2))
        c  = f'  // {r["ascii"]}' if r["ascii"] else ""
        lines.append(f'        $s{i} = {{ {hs} }}{c}')
    lines += ['    condition:', '        any of them', '}']
    return "\n".join(lines)


# cli
def main():
    p = argparse.ArgumentParser(
        description="Find byte sequences in ALL G1 files but ABSENT from all G2 files.")
    p.add_argument("--g1",  nargs="+", required=True, metavar="FILE")
    p.add_argument("--g2",  nargs="*", default=[],    metavar="FILE")
    p.add_argument("--min-len",   type=int, default=8,  metavar="N")
    p.add_argument("--max-len",   type=int, default=32, metavar="N")
    p.add_argument("--top",       type=int, default=20, metavar="K")
    p.add_argument("--step",      type=int, default=4,  metavar="S",
                   help="Sliding-window step (default 4; 1 for exhaustive but slow)")
    p.add_argument("--out",        metavar="FILE", help="JSON output")
    p.add_argument("--yara",       metavar="FILE", help="YARA rule output")
    p.add_argument("--yara-name",  default="distinctive_g1")
    p.add_argument("--no-unzip",   action="store_true",
                   help="Treat APK/ZIP as raw bytes, don't extract inner files")
    p.add_argument("--quiet",      action="store_true")
    args = p.parse_args()

    for path in args.g1 + args.g2:
        if not Path(path).is_file():
            print(f"[!] File not found: {path}", file=sys.stderr)
            sys.exit(1)

    results = find_distinctive(
        g1_paths=args.g1, g2_paths=args.g2,
        min_len=args.min_len, max_len=args.max_len,
        step=args.step, unzip=not args.no_unzip,
        verbose=not args.quiet,
    )

    top = results[:args.top]
    print(f"\n{'='*60}")
    print(f"TOP {len(top)} DISTINCTIVE SEQUENCES")
        
    print(f"{'='*60}")
    for i, r in enumerate(top, 1):
        note = f'  [{r["ascii"]}]' if r["ascii"] else ""
        print(f"  {i:3}. ({r['length']:3}B) {r['hex']}{note}")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[*] Full results → {args.out}")

    if args.yara:
        with open(args.yara, "w") as f:
            f.write(to_yara(results, args.yara_name))
        print(f"[*] YARA rule   → {args.yara}")

    print(f"[*] Total: {len(results):,} distinctive sequences")


if __name__ == "__main__":
    main()
