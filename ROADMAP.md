# attackmap — Roadmap

This document describes the planned release schedule for attackmap. Each version ships one feature.

Current version: **v1.1**

---

## v1.2 — Interactive HTML output

**Feature: Interactive HTML heatmap**

Add a `html` output format producing a fully self-contained interactive heatmap.

- New `render_html(columns, header_spans, title, output_path)` function, parallel to `render_heatmap`
- Pure HTML/CSS/JS implementation (no external dependencies, no Plotly)
- **Cell click** → opens technique details in a sidebar panel (name, ID, score, full layer comment, direct link to MITRE ATT&CK)
- Continuous color gradient matching the matplotlib colormap (`#f5f5f5` -> `#ffcccc` -> `#ff6666` -> `#cc0000`)
- Output: single self-contained `.html` file with zero external dependencies
- `--format` gains `html` as a valid choice alongside `png`, `svg`, `pdf`, `all`
- `--format all` now generates PNG, SVG, PDF, **and** HTML
- Existing static rendering pipeline (`render_heatmap`) is unchanged
- `--version` flag

---

## v1.3 — TBD

Planned features (not yet scheduled):

- ...

---

## Summary

| Version | Feature                  | Status  |
|---------|--------------------------|---------|
| v1.1    | `--min-score` CLI filter | Shipped |
| v1.2    | Interactive HTML output  | WIP     |