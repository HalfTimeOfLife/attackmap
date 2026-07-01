# attackmap

A lightweight Python tool that converts MITRE ATT&CK Navigator layers into publication-ready heatmaps.

Technique names and tactic assignments are resolved dynamically from the official MITRE ATT&CK Enterprise STIX bundle.

Supported output formats:
- **PNG**
- **SVG**
- **PDF**
- **HTML**

---

## Features

- Parses MITRE ATT&CK Navigator layer (Enterprise, v4.5+)
- Resolves technique metadata dynamically from official MITRE ATT&CK STIX bundle (tested with ATT&CK v19)
- Automatically balances dense tactic columns into adaptive sub-columns while preserving ATT&CK tactic grouping
- Techniques mapped to multiple tactics are automatically rendered in every applicable tactic
- Analyst-defined score visualization (integer 0–100)
- Multi-format export: PNG, SVG, PDF, HTML

---

## Installation

### 1. Install dependencies

```bash
pip install matplotlib mitreattack-python
```

### 2. Download MITRE ATT&CK STIX bundle

```bash
curl -L -o enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

> Technique names and tactic assignments are resolved dynamically from the official STIX bundle.

---

## Usage

```bash
python attackmap.py \
  --layer  <layer.json> \
  --stix   <enterprise-attack.json> \
  --output <output/heatmap> \
  --title  "<Heatmap title>" \
  --format <png|svg|pdf|html|all> \
  --min-score <0-100>
```

| Argument       | Required | Default    | Description |
|---------------|----------|------------|-------------|
| `--layer`     | yes      | —          | ATT&CK Navigator JSON layer |
| `--stix`      | yes      | —          | MITRE ATT&CK STIX bundle |
| `--output`    | yes      | —          | Output path (extension overridden by format) |
| `--title`     | no       | Layer name | Heatmap title |
| `--format`    | no       | `png`      | Output format: `png`, `svg`, `pdf`, `html`, `all` |
| `--min-score` | no       | `0`        | Minimum score threshold (0–100) |
| `--version`   | no       | —          | Display program version and exit |

---

## Filtering by score

You can filter techniques using any analyst-defined score.

```bash
python attackmap.py \
  --layer example-layer.json \
  --stix enterprise-attack.json \
  --output heatmap \
  --min-score 80
```

Only techniques whose score is greater than or equal to 80 will be rendered.

---

## Layer format

Each technique requires:

- `techniqueID`
- `score` (integer between 0 and 100)

Supported optional fields:

- `enabled`
- `comment` (displayed in HTML output)

```json
{
  "name": "Example layer",
  "versions": {
    "attack": "19",
    "navigator": "5.1.0",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "techniques": [
    { "techniqueID": "T1566.001", "score": 100 },
    { "techniqueID": "T1055.003", "score": 90 }
  ]
}
```

---

## Output formats

### PNG / SVG / PDF

Static heatmap rendering suitable for reports and offline analysis.

![example_heatmap](./docs/example_heatmap.png)

### HTML

Interactive heatmap with:
- clickable techniques
- detail sidebar
  - technique ID
  - score
  - analyst comments
  - direct links to MITRE ATT&CK
- fully offline single-file output

---

## Project structure

```
attackmap/
├── docs/
│   ├── example_heatmap.html
│   ├── example_heatmap.pdf
│   ├── example_heatmap.png
│   └── example_heatmap.svg
├── examples/
│   └── example-layer.json
├── attackmap.py
├── README.md
├── ROADMAP.md
└── LICENSE
```
---

## License

MIT License — see [LICENSE](LICENSE) file for details.
