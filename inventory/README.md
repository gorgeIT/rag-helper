<!--
SPDX-FileCopyrightText: 2026 Michael Klamminger <https://gorgeit.com>
SPDX-License-Identifier: Apache-2.0
-->

# inventory

Part of [rag-helper](../README.md). All commands below are run from this `inventory/` folder.

| Script | What it does |
|---|---|
| `scan.py` | Scans the share and writes the inventory CSVs. Standard library only, so it runs anywhere with Python 3.8+, including in the container. |
| `report.py` | Builds a PDF report from the CSVs of a scan (see [PDF report](#pdf-report)). |

`scan.py` covers stage 1 + 2 of a RAG data analysis for an office file share:

1. **Inventory** – metadata of every file (path, size, mtime, offline flag).
2. **Classification** – bucket per file, ingest class (`text` / `ocr` / `check` / `no`),
   junk/backup detection and flagging of potentially sensitive (DSGVO) folders.

File contents are not read, except with `--probe-pdf`, which opens the first pages of
PDFs to tell text-layer PDFs from scans. The script never modifies, moves or deletes
anything on the share; it only writes three CSV files:

| File                    | Content                                           |
|-------------------------|---------------------------------------------------|
| `<out>_inventory.csv`   | one row per file                                  |
| `<out>_summary.csv`     | aggregated by bucket/extension and by top folder  |
| `<out>_errors.csv`      | paths that could not be read                      |

CSVs use `;` and UTF-8 with BOM so they open directly in German Excel.

The classification rules (extensions, junk patterns, sensitive folder names) are at the
top of `scan.py` – review and adjust them for the office before running.

### Skipped folders

These folders are never entered (names are case-insensitive; see `SKIP_DIRS` in `scan.py`):

| Kind                    | Folder names                                                                 |
|-------------------------|------------------------------------------------------------------------------|
| Snapshots               | `.snapshot` `~snapshot` `#snapshot` `.zfs` `.snapshots`                      |
| Trash / recycle bin     | `$RECYCLE.BIN` `RECYCLER` `#recycle` `@Recycle` `.recycle` `.Trash` `.Trash-*` `.Trashes` `.TemporaryItems` |
| System / NAS / sync     | `System Volume Information` `DfsrPrivate` `@eaDir` `.fseventsd` `.Spotlight-V100` `.DocumentRevisions-V100` `.dropbox.cache` `.glusterfs` |
| Version control         | `.git` `.svn` `.hg` `.bzr` `_darcs` `CVS`                                    |
| Dependencies / caches   | `node_modules` `bower_components` `__pycache__` `.venv` `venv` `.tox` `.nox` `.mypy_cache` `.pytest_cache` `.ruff_cache` `.gradle` `.m2` `.npm` `.yarn` `.pnpm-store` `.terraform` `.next` `.nuxt` `.parcel-cache` `.angular` `.sass-cache` `.cache` |

Generic names such as `cache`, `tmp`, `build`, `bin` or `trash` are deliberately **not**
skipped by default, because in an office they can contain real project data. Add them per
run with `--skip-dir` (repeatable, exact name or pattern; no image rebuild needed):

```sh
... rag-inventory /data --out office --skip-dir cache --skip-dir 'tmp*' --skip-dir trash
```

The number of skipped folders is printed at the end of the run.

## Running with Podman

### 1. Build the image

```sh
podman build -t rag-inventory .
```

### 2. Mount the share read-only on the host

The container must only ever see the share read-only. Mount it `ro` on the host **and**
pass it into the container with `:ro` – two independent layers of protection.

```sh
sudo mkdir -p /mnt/share
sudo mount -t cifs //fileserver/daten /mnt/share \
    -o ro,noatime,username=USER,domain=DOMAIN,uid=$(id -u),gid=$(id -g),vers=3.0
```

`uid`/`gid` make the files appear as owned by your user, so rootless Podman can read them.

### 3. Run the analysis

```sh
mkdir -p results
podman run --rm \
    --network=none \
    --read-only \
    --security-opt label=disable \
    -v /mnt/share:/data:ro \
    -v ./results:/out \
    rag-inventory /data --out office
```

With PDF probing (10 % sample):

```sh
podman run --rm --network=none --read-only --security-opt label=disable \
    -v /mnt/share:/data:ro -v ./results:/out \
    rag-inventory /data --out office --probe-pdf --pdf-sample 0.1
```

Results end up in `./results/office_*.csv`. Progress is printed to stderr every 20 000 files.
For long runs add `-d --name rag` and follow with `podman logs -f rag`.

What the options do:

| Option                           | Why                                                                 |
|----------------------------------|---------------------------------------------------------------------|
| `-v /mnt/share:/data:ro`         | share is read-only inside the container                             |
| `-v ./results:/out`              | the only writable location; CSVs are written here                   |
| `--network=none`                 | the container has no network access – no data can leave the machine |
| `--read-only`                    | the container's own filesystem is read-only as well                 |
| `--security-opt label=disable`   | needed on SELinux hosts (Fedora/RHEL): CIFS mounts cannot be relabeled, so `:z` does not work for the share. Alternatively mount the share with `-o context=system_u:object_r:container_file_t:s0` and use `-v ./results:/out:z` |

Run Podman **rootless** (as your normal user, no `sudo`). Container root then maps to
your host user: it can read what you can read on the share, and the CSVs in `./results`
are owned by you.

### Rootful Podman (local folders your user cannot read)

If local permissions are the problem, for example on a local disk or ZFS pool, run as
root. Give root only the right to *read* everything, not to override all permissions:

```sh
sudo podman build -t rag-inventory .   # rootful Podman has its own image store
sudo mkdir -p results                   # must be owned by root, so root can write without DAC_OVERRIDE

sudo podman run -d --replace --name rag \
    --network=none --read-only \
    --security-opt label=disable \
    --cap-drop=all --cap-add=DAC_READ_SEARCH \
    -v /srv/data:/data:ro \
    -v ./results:/out \
    rag-inventory /data --out office --probe-pdf --pdf-sample 0.1

sudo podman logs -f rag                 # progress; remove with: sudo podman rm rag
sudo chown -R $(id -u):$(id -g) results
```

Don't combine `-d` with `--rm`: the container and its logs disappear as soon as it
exits, including any error message.

This does **not** help on a CIFS share: there, the file server decides access based on
the SMB account used for the mount. Use an account with read access to everything
instead, or a Backup Operators account with the `backupuid=` mount option.

### Show all options

```sh
podman run --rm rag-inventory --help
```

## Running without a container

Python 3.8+, no dependencies (`pypdf` only for `--probe-pdf`). With [uv](https://docs.astral.sh/uv/),
`pypdf` is pulled into a temporary environment on demand:

```sh
uv run scan.py /mnt/share --out office
uv run --with pypdf scan.py /mnt/share --out office --probe-pdf --pdf-sample 0.1
```

On Windows it can run directly against a UNC path (long paths are supported):

```bat
uv run scan.py \\fileserver\daten --out office
```

## PDF report

`report.py` turns the CSVs of a run into a PDF report with these sections:
1. overview
2. ingest classes
3. top folders
4. file types
5. exclusions and sensitive folders
6. file age
7. unreadable paths

It works the same for plain and anonymized runs, and the overview says which kind it is.

```sh
uv run report.py results/office      # -> results/office_report.pdf
uv run report.py results/office --title "Example Office" --out office_report.pdf
```

The dependencies (pandas, pyarrow, matplotlib, reportlab) are declared inside the
script, so `uv run` installs them on the first call. A run with 2 million files takes
under a minute and needs about 1 GB of RAM. Unlike `scan.py`, `report.py` is not part of
the container image.

## Anonymized run – handout for the IT provider

Use this when the script is run by the office's IT provider and the results are handed
to a third party who must not see real file or folder names (e.g. before a data
processing agreement is in place).

### What the script does and does not do

- It only **reads metadata**: names, sizes, dates. It never changes, moves or deletes
  anything on the share, and in the container it has no network access.
- With `--probe-pdf` it opens PDFs and extracts the text of the **first 2 pages in
  memory**, only to count characters (text PDF vs. scan). No text is written anywhere.
- With `--anonymize`, **every file and folder name** in all output files is replaced by a
  pseudonym such as `d_3f2a91bc07e4d5a6` (folder) or `f_c19d4e0a8b7f6e21.pdf` (file).
  The pseudonym is an HMAC-SHA256 of the name with a secret key, so it cannot be
  reversed or guessed without the key. The folder structure and file extensions are kept.
  The same name always gets the same pseudonym (e.g. a `Pläne` folder in every project).
  Error messages are reduced to the error type and number, because they contain paths.
- With `--coarse`, dates are rounded to the month, sizes to 2 significant digits
  (1,234,567 → 1,200,000), and the PDF character count is dropped.

The **key file stays with you** (the IT provider) and is never handed over. Keep it for
later runs: with the same key, the pseudonyms stay identical, so runs can be compared,
and you can look up a folder if the recipient asks about a pseudonym. Delete it when the
project is over. The script refuses to put the key next to the results.

### Steps (Linux, Podman)

```sh
# 1. build the image (once)
podman build -t rag-inventory .

# 2. mount the share read-only (see "Running with Podman" above), then:
#    Both folders must exist before the run - Podman does not create bind-mount folders
#    ("Error: lstat anon-key: no such file or directory"). The key itself is created by
#    the script on the first run (random, 256 bit) and reused on later runs.
mkdir -p results anon-key
chmod 700 anon-key

# 3. run
podman run --rm --network=none --read-only --security-opt label=disable \
    -v /mnt/share:/data:ro \
    -v ./results:/out \
    -v ./anon-key:/key \
    rag-inventory /data --out office \
        --anonymize --anon-key /key/office.key --coarse \
        --probe-pdf --pdf-sample 0.1
```

On Windows, without a container (Python 3.8+, `pypdf` only for `--probe-pdf`):

```bat
uv run --with pypdf scan.py \\fileserver\daten --out results\office --anonymize --anon-key C:\secure\office.key --coarse --probe-pdf --pdf-sample 0.1
```

### 4. Check before handing over

Search the results for a few names you know are on the share, such as a client, a
project or an employee. There should be no matches:

```sh
grep -il -e "huber" -e "projekt" results/office_*.csv || echo "OK: no matches"
```

### 5. Hand over

Hand over **only** `results/office_inventory.csv`, `office_summary.csv` and `office_errors.csv`.
**Never** hand over `anon-key/office.key`.

If you don't want to hand over data on individual files at all, send only
`office_summary.csv`. It contains just totals per file type and per (pseudonymized) top folder.

### Optional: readable top-level folders

If the top-level folder names are harmless (e.g. `Projekte`, `Verwaltung`, `Archiv`)
and you approve them, add `--keep-levels 1`. The first folder level then stays readable,
and everything below is still pseudonymized. Check the names first, e.g. with `ls /mnt/share`.

### Output columns

`rel_path` (pseudonymized), `top_folder` (pseudonymized), `depth`, `name` (pseudonymized),
`ext`, `size_bytes`, `mtime`, `bucket`, `ingest`, `exclude_reason`, `sensitive`, `offline`,
`pdf_pages`, `pdf_probe_chars`. `sensitive`/`exclude_reason` are computed from the real
names *before* they are pseudonymized, e.g. `sensitive=yes` for files below a folder
named like `*personal*` or `*lohn*`; the list of name patterns is at the top of `scan.py`.

## Notes

- **Offline / HSM / cloud-tiered files**: on Windows these are detected and never opened
  by `--probe-pdf`. On Linux (CIFS mount) the offline attribute is not visible, so
  `--probe-pdf` may trigger a recall of archived PDFs. Use `--pdf-sample` to limit this,
  or run the probe on Windows.
- Output files with the same `--out` prefix are overwritten without asking.
