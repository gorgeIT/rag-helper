#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Michael Klamminger <https://gorgeit.com>
# SPDX-License-Identifier: Apache-2.0
"""
scan.py - Stage 1 + 2 of the RAG data analysis.

Stage 1: metadata inventory of a file share (path, size, mtime, ...)
Stage 2: classification of every file into an ingest bucket, junk/backup
         detection and flagging of potentially sensitive (DSGVO) folders.

File contents are NOT read, unless --probe-pdf is given. In that case PDFs
are opened (first pages only) to decide text layer vs. scan (needs pypdf).

Runs on Linux (share mounted via CIFS, read-only) or directly on Windows
against a UNC path (\\\\server\\share). Python 3.8+, no dependencies
except optional pypdf.

Output:
  <out>_inventory.csv   one row per file
  <out>_summary.csv     aggregated by bucket/extension and by top folder
  <out>_errors.csv      paths that could not be read

With --anonymize every file and folder name in all three outputs is replaced
by a keyed hash (HMAC-SHA256, key in --anon-key, which stays with whoever runs
the script). Structure and extensions are kept. --coarse additionally rounds
dates to the month and sizes to 2 significant digits.

Examples:
  python3 scan.py /mnt/share --out office
  python scan.py \\\\fileserver\\daten --out office --probe-pdf --pdf-sample 0.1
  python3 scan.py /mnt/share --out office --anonymize --anon-key /secret/office.key --coarse
"""
import argparse
import csv
import fnmatch
import functools
import hashlib
import hmac
import logging
import os
import secrets
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Classification rules - adjust to the office before running
# --------------------------------------------------------------------------
EXT_BUCKETS = {
    "text_native": ".doc .docx .docm .dot .dotx .odt .rtf .txt .md .xls .xlsx .xlsm "
                   ".xlsb .ods .csv .tsv .ppt .pptx .pptm .odp .htm .html .xml .json",
    "email":       ".msg .eml",
    "pdf":         ".pdf",
    "ocr_candidate": ".tif .tiff",
    "design":      ".indd .idml .ai .psd .afdesign .afpub .eps",
    "cad_bim":     ".dwg .dxf .dwf .dwfx .rvt .rfa .rte .rft .pln .pla .tpl .ifc .ifczip "
                   ".skp .3dm .3ds .max .c4d .blend .fbx .obj .vwx .dgn .nwd .nwc .nwf .plt .ctb .stb",
    "pointcloud":  ".e57 .las .laz .rcp .rcs .pts .xyz",
    "image":       ".jpg .jpeg .png .gif .bmp .webp .heic .svg .raw .cr2 .cr3 .nef .arw .dng .exr .hdr",
    "video":       ".mp4 .mov .avi .mkv .wmv .m4v .mpg .mpeg",
    "audio":       ".mp3 .wav .m4a .aac .flac .wma",
    "archive":     ".zip .7z .rar .tar .gz .tgz .bz2",
    "mail_archive": ".pst .ost .mbox",
    "database":    ".mdb .accdb .sqlite .db",
    "binary":      ".exe .msi .dll .dmg .bin .sys .jar .cab .iso .img .vhd .vhdx",
}

# bucket -> ingest class: text / ocr / check / no
INGEST_CLASS = {
    "text_native": "text", "email": "text", "pdf_text": "text",
    "pdf_scanned": "ocr", "ocr_candidate": "ocr",
    "pdf_unprobed": "check", "pdf_encrypted": "check", "pdf_error": "check",
    "design": "check", "cad_bim": "check", "archive": "check",
    "mail_archive": "check", "database": "check", "unknown": "check",
    "pointcloud": "no", "image": "no", "video": "no", "audio": "no", "binary": "no",
}

# Directories that are never descended into (lower-case exact names).
# Only unambiguous names - generic ones like "cache", "build", "bin", "tmp" can
# be real project data in an office; add those per run with --skip-dir.
SKIP_DIRS = {
    # snapshots (NetApp, Synology, ZFS, btrfs/snapper)
    ".snapshot", "~snapshot", "#snapshot", ".zfs", ".snapshots",
    # trash / recycle bins (Windows, NAS, macOS, freedesktop)
    "$recycle.bin", "recycler", "#recycle", "@recycle", ".recycle",
    ".trash", ".trashes", ".temporaryitems",
    # OS / NAS / sync system folders
    "system volume information", "dfsrprivate", "@eadir", ".fseventsd",
    ".spotlight-v100", ".documentrevisions-v100", ".dropbox.cache", ".glusterfs",
    # version control
    ".git", ".svn", ".hg", ".bzr", "_darcs", "cvs",
    # dependency / build artefacts and caches
    "node_modules", "bower_components", "__pycache__", ".venv", "venv", ".tox",
    ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".gradle", ".m2",
    ".npm", ".yarn", ".pnpm-store", ".terraform", ".next", ".nuxt",
    ".parcel-cache", ".angular", ".sass-cache", ".cache",
}
# Same, as lower-case fnmatch patterns (checked only if no exact match)
SKIP_DIR_PATTERNS = [".trash-*"]

# File name patterns -> exclude reason (lower-case fnmatch)
JUNK_FILES = [
    ("~$*", "office_lock"), ("thumbs.db", "system"), ("desktop.ini", "system"),
    (".ds_store", "system"), ("._*", "system"), ("*.lnk", "shortcut"),
    ("*.tmp", "temp"), ("~*", "temp"), ("*.bak", "backup"), ("*.old", "backup"),
    ("*.dwl", "cad_lock"), ("*.dwl2", "cad_lock"), ("*.sv$", "cad_autosave"),
    ("*.ac$", "cad_temp"), ("*.bpn", "archicad_backup"), ("*.lck", "lock"),
    ("*.[0-9][0-9][0-9][0-9].rvt", "revit_backup"),
    ("*.[0-9][0-9][0-9][0-9].rfa", "revit_backup"),
]

# Directory name patterns -> exclude reason (inherited by all children)
JUNK_DIRS = [("*backup*", "backup_folder"), ("*sicherung*", "backup_folder"),
             ("*autosave*", "autosave_folder"), ("*_bak", "backup_folder")]

# Directory name patterns that flag potentially sensitive content (review!)
SENSITIVE_DIRS = ["*personal*", "hr", "hr_*", "*_hr", "*lohn*", "*gehalt*",
                  "*gehälter*", "*bewerbung*", "*privat*", "*private*",
                  "*payroll*", "*salary*", "*krank*", "*arzt*",
                  "*buchhaltung*", "*steuer*", "*vertrag*", "*verträge*"]

# --------------------------------------------------------------------------
EXT_TO_BUCKET = {e: b for b, exts in EXT_BUCKETS.items() for e in exts.split()}
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000


def match_first(name, rules):
    for pattern, reason in rules:
        if fnmatch.fnmatchcase(name, pattern):
            return reason
    return ""


def is_sensitive(name):
    return any(fnmatch.fnmatchcase(name, p) for p in SENSITIVE_DIRS)


def is_skipped(name):
    return name in SKIP_DIRS or any(fnmatch.fnmatchcase(name, p) for p in SKIP_DIR_PATTERNS)


def iso_date(ts):
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).date().isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def prep_root(root):
    root = os.path.abspath(root)
    if os.name == "nt" and not root.startswith("\\\\?\\"):
        # long path support (>260 chars) on Windows
        root = "\\\\?\\UNC\\" + root[2:] if root.startswith("\\\\") else "\\\\?\\" + root
    return root.rstrip("\\/") or root


def in_sample(rel, rate):
    if rate >= 1.0:
        return True
    h = int(hashlib.md5(rel.encode("utf-8", "surrogateescape")).hexdigest()[:8], 16)
    return h / 0xFFFFFFFF < rate


def probe_pdf(path, max_pages, min_chars):
    """Return (bucket, page_count, chars_in_probed_pages)."""
    from pypdf import PdfReader
    try:
        r = PdfReader(path)
        if r.is_encrypted:
            try:
                if not r.decrypt(""):
                    return "pdf_encrypted", "", ""
            except Exception:
                return "pdf_encrypted", "", ""
        n = len(r.pages)
        chars = 0
        for i in range(min(max_pages, n)):
            chars += len((r.pages[i].extract_text() or "").strip())
        return ("pdf_text" if chars >= min_chars else "pdf_scanned"), n, chars
    except Exception:
        return "pdf_error", "", ""


def load_key(path):
    """Read the hex HMAC key from path, or create a new random one there."""
    if os.path.exists(path):
        with open(path) as f:
            key = bytes.fromhex(f.read().strip())
        if len(key) < 16:
            sys.exit(f"anon key in {path} is too short")
        print(f"using existing anon key {path}", file=sys.stderr)
        return key
    key = secrets.token_bytes(32)
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
        f.write(key.hex() + "\n")
    print(f"created new anon key {path} - keep it, never hand it over", file=sys.stderr)
    return key


class Pseudonymizer:
    """Replaces path segments by keyed hashes; the same name always gets the same pseudonym."""

    def __init__(self, key, keep_levels):
        self.key = key
        self.keep_levels = keep_levels
        self.segment = functools.lru_cache(maxsize=65536)(self._segment)

    def _segment(self, name):
        return hmac.new(self.key, name.encode("utf-8", "surrogateescape"),
                        hashlib.sha256).hexdigest()[:16]

    def file(self, name):
        return "f_" + self.segment(name) + os.path.splitext(name)[1].lower()

    def dir(self, name, level):
        return name if level < self.keep_levels else "d_" + self.segment(name)

    def path(self, rel, is_file):
        if not rel:
            return ""
        parts = rel.replace("\\", "/").split("/")
        out = [self.dir(p, i) for i, p in enumerate(parts[:-1])]
        out.append(self.file(parts[-1]) if is_file else self.dir(parts[-1], len(parts) - 1))
        return "/".join(out)


def coarse_size(n):
    """Round to 2 significant digits (1234567 -> 1200000)."""
    if n < 100:
        return n
    e = 10 ** (len(str(n)) - 2)
    return (n + e // 2) // e * e


def walk(root, on_error, stats):
    """Iterative scandir walk. Yields (entry, stat, dir_exclude, dir_sensitive)."""
    stack = [(root, "", False)]
    while stack:
        d, d_excl, d_sens = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            lname = e.name.lower()
                            if is_skipped(lname):
                                stats["skipped_dirs"] += 1
                                continue
                            excl = d_excl or match_first(lname, JUNK_DIRS)
                            sens = d_sens or is_sensitive(lname)
                            stack.append((e.path, excl, sens))
                        elif e.is_file(follow_symlinks=False):
                            yield e, e.stat(follow_symlinks=False), d_excl, d_sens
                    except OSError as ex:
                        on_error(e.path, ex)
                        stats["errors"] += 1
        except OSError as ex:
            on_error(d, ex)
            stats["errors"] += 1


def main():
    ap = argparse.ArgumentParser(description="RAG pre-analysis: inventory + classification")
    ap.add_argument("root", help="share root (mount point or UNC path)")
    ap.add_argument("--out", default="rag_inventory", help="output file prefix")
    ap.add_argument("--delimiter", default=";", help="CSV delimiter (default ';' for German Excel)")
    ap.add_argument("--probe-pdf", action="store_true", help="open PDFs to detect text layer (needs pypdf)")
    ap.add_argument("--pdf-sample", type=float, default=1.0, help="fraction of PDFs to probe (0..1)")
    ap.add_argument("--pdf-max-mb", type=float, default=100, help="skip probing PDFs larger than this")
    ap.add_argument("--pdf-pages", type=int, default=2, help="pages to probe per PDF")
    ap.add_argument("--min-chars", type=int, default=50, help="chars in probed pages to count as text PDF")
    ap.add_argument("--skip-dir", action="append", default=[], metavar="NAME",
                    help="additional directory name or fnmatch pattern to skip "
                         "(case-insensitive, repeatable), e.g. --skip-dir cache --skip-dir 'tmp*'")
    ap.add_argument("--anonymize", action="store_true",
                    help="replace all file/folder names in the output by keyed hashes (needs --anon-key)")
    ap.add_argument("--anon-key", metavar="FILE",
                    help="HMAC key file; created if missing, reuse it for comparable runs. "
                         "Must not be in the output directory - it must never be handed over")
    ap.add_argument("--keep-levels", type=int, default=0, metavar="N",
                    help="with --anonymize: keep the first N folder levels readable (default 0)")
    ap.add_argument("--coarse", action="store_true",
                    help="round mtime to the month and sizes to 2 significant digits, "
                         "drop pdf_probe_chars")
    args = ap.parse_args()

    anon = None
    if args.anonymize:
        if not args.anon_key:
            sys.exit("--anonymize needs --anon-key FILE (outside the output directory)")
        out_dir = os.path.dirname(os.path.abspath(args.out + "_x"))
        if os.path.dirname(os.path.abspath(args.anon_key)) == out_dir:
            sys.exit("--anon-key must not be in the output directory, "
                     "or it would be handed over together with the results")
        anon = Pseudonymizer(load_key(args.anon_key), args.keep_levels)
    elif args.keep_levels or args.anon_key:
        sys.exit("--keep-levels and --anon-key only make sense with --anonymize")

    for name in args.skip_dir:
        name = name.lower()
        if any(c in name for c in "*?["):
            SKIP_DIR_PATTERNS.append(name)
        else:
            SKIP_DIRS.add(name)

    if args.probe_pdf:
        try:
            import pypdf  # noqa: F401
            logging.getLogger("pypdf").setLevel(logging.ERROR)
        except ImportError:
            sys.exit("--probe-pdf needs pypdf:  uv run --with pypdf scan.py ...")

    root = prep_root(args.root)
    if not os.path.isdir(root):
        sys.exit(f"not a directory: {args.root}")

    stats = defaultdict(int)
    agg_ext = defaultdict(lambda: [0, 0, None, None, 0])   # files, bytes, oldest, newest, pdf_pages
    agg_top = defaultdict(lambda: [0, 0, None, None, 0])
    t0 = time.time()
    enc = "utf-8-sig"  # BOM so Excel shows umlauts correctly

    with open(f"{args.out}_inventory.csv", "w", newline="", encoding=enc, errors="replace") as fi, \
         open(f"{args.out}_errors.csv", "w", newline="", encoding=enc, errors="replace") as fe:
        inv = csv.writer(fi, delimiter=args.delimiter)
        err = csv.writer(fe, delimiter=args.delimiter)
        inv.writerow(["rel_path", "top_folder", "depth", "name", "ext", "size_bytes", "mtime",
                      "bucket", "ingest", "exclude_reason", "sensitive", "offline",
                      "pdf_pages", "pdf_probe_chars"])
        err.writerow(["path", "error", "message"])

        def on_error(path, ex):
            if anon:
                # the message repeats the path, so only the errno is kept
                rel = path[len(root):].lstrip("\\/")
                err.writerow([anon.path(rel, is_file=False) or "(root)", type(ex).__name__,
                              f"errno {ex.errno}" if ex.errno is not None else ""])
            else:
                err.writerow([path, type(ex).__name__, str(ex)])

        for e, st, d_excl, d_sens in walk(root, on_error, stats):
            rel = e.path[len(root):].lstrip("\\/")
            parts = rel.replace("\\", "/").split("/")
            top = parts[0] if len(parts) > 1 else "(root)"
            lname = e.name.lower()
            ext = os.path.splitext(lname)[1]
            size = st.st_size
            mdate = iso_date(st.st_mtime)
            attrs = getattr(st, "st_file_attributes", 0)
            offline = bool(attrs & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS))

            bucket = EXT_TO_BUCKET.get(ext, "unknown")
            pages = chars = ""
            if bucket == "pdf":
                bucket = "pdf_unprobed"
                if (args.probe_pdf and not offline and size <= args.pdf_max_mb * 1e6
                        and in_sample(rel, args.pdf_sample)):
                    bucket, pages, chars = probe_pdf(e.path, args.pdf_pages, args.min_chars)
                    stats["pdf_probed"] += 1

            excl = match_first(lname, JUNK_FILES) or d_excl
            ingest = "no" if excl else INGEST_CLASS[bucket]

            # everything above works on the real names; only the output is pseudonymized
            out_rel, out_name, out_size = rel, e.name, size
            if anon:
                out_rel, out_name = anon.path(rel, is_file=True), anon.file(e.name)
                if top != "(root)":
                    top = anon.dir(top, 0)
            if args.coarse:
                mdate, out_size, chars = mdate[:7], coarse_size(size), ""

            inv.writerow([out_rel, top, len(parts) - 1, out_name, ext, out_size, mdate, bucket,
                          ingest, excl, "yes" if d_sens else "", "yes" if offline else "",
                          pages, chars])

            for agg, key in ((agg_ext, (bucket, ext, ingest)), (agg_top, (top, bucket, ingest))):
                a = agg[key]
                a[0] += 1
                a[1] += size
                if mdate:
                    a[2] = mdate if a[2] is None or mdate < a[2] else a[2]
                    a[3] = mdate if a[3] is None or mdate > a[3] else a[3]
                if pages:
                    a[4] += pages

            stats["files"] += 1
            stats["bytes"] += size
            if stats["files"] % 20000 == 0:
                dt = time.time() - t0
                print(f"{stats['files']:>10,} files  {stats['bytes']/1e9:8.1f} GB  "
                      f"{stats['files']/dt:6.0f} files/s  errors={stats['errors']}",
                      file=sys.stderr, flush=True)

    with open(f"{args.out}_summary.csv", "w", newline="", encoding=enc) as fs:
        w = csv.writer(fs, delimiter=args.delimiter)
        w.writerow(["group_by", "key1", "key2", "ingest", "files", "bytes", "gb",
                    "oldest", "newest", "pdf_pages_probed"])
        for label, agg in (("bucket/ext", agg_ext), ("top_folder/bucket", agg_top)):
            for (k1, k2, ing), (n, b, old, new, pg) in sorted(agg.items(), key=lambda x: -x[1][1]):
                w.writerow([label, k1, k2, ing, n, b, f"{b/1e9:.3f}".replace(".", ","
                            if args.delimiter == ";" else "."), old or "", new or "", pg or ""])

    dt = time.time() - t0
    by_ingest = defaultdict(lambda: [0, 0])
    for (_, _, ing), (n, b, *_rest) in agg_ext.items():
        by_ingest[ing][0] += n
        by_ingest[ing][1] += b
    print(f"\nDone in {dt/60:.1f} min: {stats['files']:,} files, {stats['bytes']/1e12:.2f} TB, "
          f"{stats['errors']} errors, {stats['skipped_dirs']} system dirs skipped, "
          f"{stats['pdf_probed']} PDFs probed", file=sys.stderr)
    for ing in ("text", "ocr", "check", "no"):
        n, b = by_ingest.get(ing, (0, 0))
        print(f"  ingest={ing:<6} {n:>10,} files  {b/1e9:10.1f} GB", file=sys.stderr)


if __name__ == "__main__":
    main()

