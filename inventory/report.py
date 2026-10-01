#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Michael Klamminger <https://gorgeit.com>
# SPDX-License-Identifier: Apache-2.0
# /// script
# requires-python = ">=3.9"
# dependencies = ["pandas>=2", "pyarrow", "matplotlib", "reportlab"]
# ///
"""
report.py - PDF report from the output of scan.py (rag-inventory).

Reads <prefix>_inventory.csv and <prefix>_errors.csv and writes
<prefix>_report.pdf with the same sections as the analysis notebook:
ingest classes, top folders, file types, exclusions / sensitive folders,
file age, errors. Works the same for plain and --anonymize/--coarse runs.

Examples:
  uv run report.py results/office
  uv run report.py results/office --title "Example Office" --out office_report.pdf
"""
import argparse
import io
import os
import sys
from datetime import date

# Arrow's default memory pool made load + pivot ~10x slower here (most of it system time);
# the system allocator avoids that. Must be set before pyarrow is imported.
os.environ.setdefault("ARROW_DEFAULT_MEMORY_POOL", "system")

import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import cm  # noqa: E402
from reportlab.platypus import (Image, KeepTogether, Paragraph, SimpleDocTemplate,  # noqa: E402
                                Spacer, Table, TableStyle)

ORDER = ["text", "ocr", "check", "no"]
INGEST_TEXT = {
    "text": "ingest directly",
    "ocr": "needs OCR",
    "check": "manual decision",
    "no": "excluded",
}
MAX_ROWS = 25          # longer tables are cut, the rest is summed up as "(other)"
PAGE_W = A4[0] - 3 * cm

styles = getSampleStyleSheet()
H1, H2, BODY, SMALL = styles["Title"], styles["Heading2"], styles["BodyText"], styles["Italic"]


# --------------------------------------------------------------------------
# data
# --------------------------------------------------------------------------
def load(prefix, delimiter):
    kw = dict(sep=delimiter, encoding="utf-8-sig")
    try:
        inv = pd.read_csv(f"{prefix}_inventory.csv", engine="pyarrow", **kw)
    except (ImportError, ValueError):
        inv = pd.read_csv(f"{prefix}_inventory.csv", low_memory=False, **kw)
    inv["rel_path"] = inv["rel_path"].astype("string[pyarrow]")
    for c in ["top_folder", "ext", "bucket", "ingest", "exclude_reason"]:
        inv[c] = inv[c].fillna("").astype(str).astype("category")
    inv["sensitive"] = inv["sensitive"].eq("yes")
    # mtime is YYYY-MM-DD, or YYYY-MM with --coarse
    inv["year"] = pd.to_numeric(inv["mtime"].astype(str).str[:4], errors="coerce")
    inv["gb"] = inv["size_bytes"] / 1e9
    inv["pdf_pages"] = pd.to_numeric(inv["pdf_pages"], errors="coerce")

    err_file = f"{prefix}_errors.csv"
    errors = pd.read_csv(err_file, **kw) if os.path.exists(err_file) else pd.DataFrame()
    return inv, errors


def agg(df, by):
    g = df.groupby(by, observed=True).agg(files=("gb", "size"), gb=("gb", "sum"))
    g["files_%"] = 100 * g["files"] / max(g["files"].sum(), 1)
    g["gb_%"] = 100 * g["gb"] / max(g["gb"].sum(), 1e-12)
    return g


def cut(df, n=MAX_ROWS, label="(other)"):
    """Keep the first n rows, sum the rest into one row."""
    if len(df) <= n:
        return df
    rest = df.iloc[n:].select_dtypes("number").sum()
    head = df.iloc[:n].copy()
    idx = (label,) + ("",) * (head.index.nlevels - 1) if head.index.nlevels > 1 else label
    head.loc[idx, rest.index] = rest.values
    return head


# --------------------------------------------------------------------------
# PDF building blocks
# --------------------------------------------------------------------------
def fmt(v, col, gb_cols):
    if pd.isna(v):
        return ""
    if isinstance(v, (int, np.integer)):
        return f"{int(v):,}"
    if isinstance(v, (float, np.floating)):
        if col.endswith("%") or col in gb_cols or not float(v).is_integer():
            return f"{v:,.2f}"
        return f"{int(v):,}"
    return str(v)


def table(df, index=True, col_widths=None, font=8, gb_cols=("gb", "total_gb")):
    """A pandas-like table: bold header, zebra rows, numbers right-aligned.
    gb_cols are always shown with 2 decimals, other whole numbers without."""
    df = df.copy()
    if index:
        df = df.reset_index()
    header = [str(c) for c in df.columns]
    rows = [[fmt(v, str(c), gb_cols) for v, c in zip(r, df.columns)]
            for r in df.itertuples(index=False)]
    cell = styles["BodyText"].clone("cell", fontSize=font, leading=font + 2)
    # long text cells (paths) wrap instead of overflowing the page
    rows = [[Paragraph(v, cell) if len(v) > 30 else v for v in r] for r in rows]
    t = Table([header] + rows, colWidths=col_widths, repeatRows=1)
    style = [
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", font),
        ("FONT", (0, 1), (-1, -1), "Helvetica", font),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, colors.black),
        ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
    ]
    numeric = [i for i, c in enumerate(df.columns) if pd.api.types.is_numeric_dtype(df[c])]
    for i in range(len(df.columns)):
        if i not in numeric:
            style.append(("ALIGN", (i, 0), (i, -1), "LEFT"))
    for r in range(1, len(rows) + 1, 2):
        style.append(("BACKGROUND", (0, r), (-1, r), colors.HexColor("#f5f5f5")))
    t.setStyle(TableStyle(style))
    return t


def chart(fig, width=PAGE_W):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=160, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    w, h = fig.get_size_inches()
    return Image(buf, width=width, height=width * h / w)


def section(title, text=None, *first):
    """Heading, intro text and the first block(s), kept together on one page."""
    out = [Paragraph(title, H2)]
    if text:
        out.append(Paragraph(text, BODY))
    out.append(Spacer(1, 4))
    return [KeepTogether(out + list(first))]


# --------------------------------------------------------------------------
# report sections (same order as the notebook)
# --------------------------------------------------------------------------
def overview(inv, errors, prefix, title):
    anonymized = inv["rel_path"].str.match(r"^(.*/)?f_[0-9a-f]{16}").mean() > 0.9
    coarse = inv["mtime"].astype(str).str.len().median() == 7
    probed = inv["bucket"].isin(["pdf_text", "pdf_scanned", "pdf_encrypted", "pdf_error"]).sum()
    facts = [
        ["Run", os.path.basename(prefix)],
        ["Files", f"{len(inv):,}"],
        ["Volume", f"{inv['gb'].sum() / 1e3:,.2f} TB"],
        ["Top folders", f"{inv['top_folder'].nunique():,}"],
        ["Unreadable paths", f"{len(errors):,}"],
        ["PDFs probed", f"{probed:,} of {inv['ext'].eq('.pdf').sum():,}"],
        ["Names", "pseudonymized (--anonymize)" if anonymized else "real names"],
        ["Dates / sizes", "coarse (month, 2 digits)" if coarse else "exact"],
    ]
    t = Table(facts, colWidths=[4 * cm, 8 * cm])
    t.setStyle(TableStyle([("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
                           ("FONT", (1, 0), (1, -1), "Helvetica", 9),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    classes = " · ".join(f"<b>{k}</b> ({v})" for k, v in INGEST_TEXT.items())
    return [Paragraph(f"RAG inventory – {title}", H1),
            Paragraph(f"Generated {date.today().isoformat()} from <i>{prefix}_inventory.csv</i>", SMALL),
            Spacer(1, 10), t, Spacer(1, 8),
            Paragraph(f"Ingest classes: {classes}.", BODY)]


def ingest_section(inv):
    by = agg(inv, "ingest").reindex(ORDER).fillna(0)
    fig, ax = plt.subplots(1, 2, figsize=(11, 3.5))
    by["files"].plot.bar(ax=ax[0], title="Files per ingest class", rot=0)
    by["gb"].plot.bar(ax=ax[1], title="GB per ingest class", rot=0)
    plt.tight_layout()
    return section("1. Ingest classes",
                   "How much of the share can go into RAG directly, needs OCR, "
                   "needs a decision, or is excluded.", table(by)) + [Spacer(1, 6), chart(fig)]


def top_section(inv):
    top = inv.pivot_table(index="top_folder", columns="ingest", values="gb", aggfunc="sum",
                          observed=True, fill_value=0).reindex(columns=ORDER, fill_value=0)
    top["total_gb"] = top.sum(axis=1)
    top["files"] = inv.groupby("top_folder", observed=True).size()
    top["text_files"] = inv[inv["ingest"] == "text"].groupby("top_folder", observed=True).size()
    top["text_files"] = top["text_files"].fillna(0).astype(int)
    top = top.sort_values("total_gb", ascending=False)
    top.columns.name = None

    shown = top.head(20)
    fig, ax = plt.subplots(figsize=(10, max(2.5, 0.35 * len(shown) + 1)))
    shown[ORDER].plot.barh(stacked=True, ax=ax, title="GB per top folder and ingest class")
    ax.invert_yaxis()
    plt.tight_layout()
    note = f" Showing the largest {MAX_ROWS} of {len(top)}." if len(top) > MAX_ROWS else ""
    return section("2. Top folders",
                   "Volume per top-level folder, split by ingest class (GB)." + note,
                   table(cut(top), gb_cols=ORDER + ["total_gb"])) + [Spacer(1, 6), chart(fig)]


def types_section(inv):
    out = section("3. File types",
                  "Buckets overall, and the largest extensions in the classes that matter for "
                  "RAG (<b>text</b>, <b>ocr</b>) and that need a decision (<b>check</b>).",
                  table(cut(agg(inv, ["bucket", "ingest"]).sort_values("gb", ascending=False))))
    for cls in ["text", "ocr", "check"]:
        sub = inv[inv["ingest"] == cls]
        if sub.empty:
            continue
        ext = agg(sub, "ext").sort_values("files", ascending=False).head(15)
        ext.index = ext.index.astype(str).where(ext.index.astype(str) != "", "(none)")
        out.append(KeepTogether([Paragraph(f"Top extensions, ingest = {cls}", styles["Heading4"]),
                                 table(ext)]))
    return out


def exclusions_section(inv):
    excl = inv[inv["exclude_reason"] != ""]
    first = (table(agg(excl, "exclude_reason").sort_values("gb", ascending=False)) if len(excl)
             else Paragraph("No files were excluded.", BODY))
    out = section("4. Exclusions and sensitive folders",
                  "Why files were excluded, and which folders were flagged as potentially "
                  "sensitive (DSGVO) – these need a manual review before ingest.", first)

    sens = inv[inv["sensitive"]]
    out += [Spacer(1, 8), Paragraph(
        f"<b>Sensitive:</b> {len(sens):,} files, {sens['gb'].sum():,.2f} GB, "
        f"{(sens['ingest'] == 'text').sum():,} of them ingest = text.", BODY)]
    if len(sens):
        folder = sens["rel_path"].str.split("/").str[:3].str.join("/")
        dirs = (sens.assign(folder=folder, is_text=sens["ingest"].eq("text"))
                    .groupby("folder").agg(files=("gb", "size"), gb=("gb", "sum"),
                                           text_files=("is_text", "sum"))
                    .sort_values("files", ascending=False).head(30))
        out += [Spacer(1, 4), KeepTogether([
            Paragraph("Flagged folders (path down to level 3)", styles["Heading4"]),
            table(dirs, col_widths=[PAGE_W - 6 * cm, 2 * cm, 2 * cm, 2 * cm])])]
    return out


def age_section(inv):
    rel = inv[inv["ingest"].isin(["text", "ocr"]) & inv["year"].notna()]
    intro = ("5. Age of RAG-relevant files",
             "Last-modified year of files with ingest <b>text</b> or <b>ocr</b> – "
             "helps decide a cut-off date for ingest.")
    if rel.empty:
        return section(*intro, Paragraph("No text/ocr files.", BODY))
    by_year = (rel.groupby([rel["year"].astype(int).rename("year"), "ingest"], observed=True)
                  .size().unstack(fill_value=0))
    by_year.columns = by_year.columns.astype(str)
    by_year.columns.name = None
    fig, ax = plt.subplots(figsize=(11, 3.5))
    by_year.plot.bar(stacked=True, ax=ax, title="text/ocr files by last-modified year")
    plt.tight_layout()
    # table as year rows; very old years are folded into one row to keep it short
    tbl = by_year.copy()
    tbl["total"] = tbl.sum(axis=1)
    if len(tbl) > 15:
        old = tbl.iloc[:-14].sum()
        tbl = pd.concat([pd.DataFrame([old], index=[f"≤ {tbl.index[-15]}"]), tbl.iloc[-14:]])
    tbl.index = tbl.index.astype(str)
    tbl.index.name = "year"
    return section(*intro, chart(fig)) + [Spacer(1, 6), table(tbl)]


def errors_section(errors):
    if errors.empty:
        return section("6. Unreadable paths", "No errors – every folder could be read.")
    by = errors.groupby("error").size().rename("count").sort_values(ascending=False).to_frame()
    return section("6. Unreadable paths",
                   f"{len(errors):,} paths could not be read, by error type:", table(by))


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.grey)
    canvas.drawString(1.5 * cm, 1 * cm, doc.title)
    canvas.drawRightString(A4[0] - 1.5 * cm, 1 * cm, f"page {doc.page}")
    canvas.restoreState()


def main():
    ap = argparse.ArgumentParser(description="PDF report from rag_inventory CSVs")
    ap.add_argument("prefix", help="output prefix used with scan.py --out (e.g. results/office)")
    ap.add_argument("--out", help="PDF file (default <prefix>_report.pdf)")
    ap.add_argument("--title", help="report title (default: the run name)")
    ap.add_argument("--delimiter", default=";", help="CSV delimiter (default ';')")
    args = ap.parse_args()

    if not os.path.exists(f"{args.prefix}_inventory.csv"):
        sys.exit(f"not found: {args.prefix}_inventory.csv")
    out = args.out or f"{args.prefix}_report.pdf"
    title = args.title or os.path.basename(args.prefix)

    plt.rcParams.update({"font.size": 9, "axes.titlesize": 10})
    inv, errors = load(args.prefix, args.delimiter)
    story = (overview(inv, errors, args.prefix, title) + ingest_section(inv) +
             top_section(inv) + types_section(inv) + exclusions_section(inv) +
             age_section(inv) + errors_section(errors))

    doc = SimpleDocTemplate(out, pagesize=A4, title=f"RAG inventory – {title}",
                            leftMargin=1.5 * cm, rightMargin=1.5 * cm,
                            topMargin=1.5 * cm, bottomMargin=1.8 * cm)
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print(f"wrote {out} ({len(inv):,} files)", file=sys.stderr)


if __name__ == "__main__":
    main()
