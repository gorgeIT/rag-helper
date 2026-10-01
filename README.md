<!--
SPDX-FileCopyrightText: 2026 Michael Klamminger <https://gorgeit.com>
SPDX-License-Identifier: Apache-2.0
-->

# rag-helper

A collection of helper scripts for preparing RAG (retrieval-augmented generation)
projects. The scripts help you find out what data an organization has, and how much of
it is worth ingesting, before anything is indexed.

## Tools

| Folder | What it does |
|---|---|
| [`inventory/`](inventory/README.md) | Inventories a file share and classifies every file for RAG ingest (`text` / `ocr` / `check` / `no`). It flags junk, backups and potentially sensitive (DSGVO/GDPR) folders, and can pseudonymize all names so a third party can analyse the results. `report.py` turns the output into a PDF report. |

Each folder is self-contained and has its own README with usage instructions.

## Requirements

- Python 3.8+ (each tool documents its own dependencies)
- [uv](https://docs.astral.sh/uv/) to run the scripts with their dependencies
- optionally [Podman](https://podman.io/) for containerized runs

## Data protection

The scripts are meant to run where the data lives, typically operated by the data
owner or their IT provider. Read-only access, no network access in containers, and
pseudonymized output are the defaults where a tool supports them. Scan results and
pseudonymization keys are excluded from this repository via `.gitignore`. Don't commit
them.

## License

Copyright 2026 Michael Klamminger (gorgeIT e.U.)

Licensed under the [Apache License, Version 2.0](LICENSE). You may use, modify and
distribute the scripts, including commercially, as long as you keep the copyright and
license notices (see [NOTICE](NOTICE)) and mark changed files. The license grants no
rights to the gorgeIT name or trademarks.

Every source file carries an [SPDX](https://spdx.dev/) header with its copyright and
license.
