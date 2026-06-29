# attackmap — Roadmap

This document describes the planned release schedule for attackmap. Each version ships one feature.

Current version: **v1.1**

---

## v1.2 — Interactive HTML output

**Feature: Interactive HTML heatmap via Plotly**

Add a `html` output format producing a fully self-contained interactive heatmap.

- New `render_html(columns, header_spans, title, output_path)` function, parallel to `render_heatmap`
- Cell hover -> tooltip displaying technique name, ID, score, and full layer comment
- Cell click -> opens the corresponding MITRE ATT&CK page (`https://attack.mitre.org/techniques/TXXXX/YYY/`)
- Output: single `.html` file with no external dependencies (`include_plotlyjs='cdn'` or `include_plotlyjs='inline'` for offline)
- `--format` gains `html` as a valid choice alongside `png`, `svg`, `pdf`, `all`
- Existing static rendering pipeline (`render_heatmap`) is unchanged
- `--version` flag

---

## Summary

| Version | Feature                  | Status  |
|---------|--------------------------|---------|
| v1.1    | `--min-score` CLI filter | Shipped |
| v1.2    | Interactive HTML output  | Planned |