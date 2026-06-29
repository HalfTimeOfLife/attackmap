import argparse
import json
import matplotlib
import os
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import LinearSegmentedColormap
from collections import defaultdict
from mitreattack.stix20 import MitreAttackData


# --- Constants -----------------------------------------------------------------

MAX_ROWS_PER_COL = 8
CELL_W   = 2.0
CELL_H   = 0.92
HEADER_H = 0.48
TITLE_H  = 0.55
CBAR_H   = 0.35
PAD      = 0.06


# --- ATT&CK enrichment ---------------------------------------------------------

def load_attack_data(stix_path):
    """Load STIX bundle for Enterprise ATT&CK.
    
    Args:
        stix_path (str): Path to the STIX bundle file.
        
    Returns:
        MitreAttackData: Loaded ATT&CK data.
    
    """
    return MitreAttackData(stix_path)

def get_tactic_order(attack):
    """Return the ordered list of tactic shortnames from x-mitre-matrix.
    
    Args:
        attack (MitreAttackData): Loaded ATT&CK data.
        
    Returns:
        list[str]: List of tactic shortnames in canonical order.

    """
    tactics_by_matrix = attack.get_tactics_by_matrix()
    
    if not tactics_by_matrix:
        return []
    
    matrix_name = next(iter(tactics_by_matrix))
    tactics = tactics_by_matrix[matrix_name]
    
    return [
        tactic.get("x_mitre_shortname") 
        for tactic in tactics 
        if tactic.get("x_mitre_shortname")
    ]

def get_technique_info(attack, tid):
    """Retrieve the tactic shortnames and display name for a given technique ID.
    
    Args:
        attack (MitreAttackData): Loaded ATT&CK data.
        tid (str): Technique ATT&CK ID (e.g., T1566.001).
        
    Returns:
        tuple[list[str], str]: A tuple containing a list of tactic shortnames
            and the technique display name.
    """
    technique = attack.get_object_by_attack_id(tid, 'attack-pattern')
    if technique is None:
        return [], ""
    
    tactics = attack.get_tactics_by_technique(technique.id)
    
    tactic_shortnames = [
        tactic.get("x_mitre_shortname")
        for tactic in tactics
        if tactic.get("x_mitre_shortname")
    ]
    
    name = technique.get("name", "")
    
    return tactic_shortnames, name


# --- Layer parsing -------------------------------------------------------------

def load_layer(layer_path):
    """Load and return the JSON layer for ATT&CK Navigator.
    
    Args:
        layer_path (str): Path to the ATT&CK Navigator JSON layer file.
        
    Returns:
        dict: Parsed JSON data from the layer file.
    
    """
    with open(layer_path, encoding="utf-8") as f:
        data = json.load(f)
    return data

def enrich_layer(layer, attack, min_score):
    """Load layer techniques and enrich them with ATT&CK tactic metadata.

    Techniques with enabled=false are skipped. Techniques belonging to
    multiple tactics are duplicated in each applicable tactic list.

    Args:
        layer (dict): Parsed ATT&CK Navigator layer JSON.
        attack (MitreAttackData): Loaded ATT&CK data.
        min_score (int): Minimum score threshold for including techniques.

    Returns:
        dict[str, list[dict]]: Mapping of tactic shortname to a list of
            technique dicts, each containing 'id', 'score', 'name', and 'comment'.
    """
    tactic_map = defaultdict(list)
    
    for technique in layer.get('techniques', []):
        tech_score = technique.get('score', 0)
        if not technique.get('enabled', True) or tech_score < min_score:
            continue

        tid = technique.get('techniqueID')
        comment = technique.get('comment', '')
        
        tactic_shortnames, name = get_technique_info(attack, tid)
        
        if not name:
            if not tid:
                print(f"[!] {tid} not found in STIX bundle - skipped")
                continue
            print(f"[!] {tid} not found in the STIX bundle. Fallback to ID as name.")
            name = tid
                        
        for shortname in tactic_shortnames:
            tactic_map[shortname].append({
                'id': tid,
                'score': tech_score,
                'name': name,
                'comment': comment
            })
            
    return tactic_map


# --- Column layout ---------------------------------------------------------------

def truncate_name(name, max_len=33):
    """Truncate a technique name at a word boundary.

    Args:
        name (str): The technique name to truncate.
        max_len (int): Maximum character length before truncation.

    Returns:
        str: Truncated name ending with '...' if it exceeded max_len,
            otherwise the original name.
    """
    if len(name) <= max_len:
        return name
    truncated = name[:max_len].rsplit(' ', 1)[0]
    return truncated + "..."

def split_tactic(shortname, display_name, techniques):
    """Split a tactic into sub-columns if it exceeds MAX_ROWS_PER_COL.

    Args:
        shortname (str): The tactic shortname used as internal key (e.g., 'defense-evasion').
        display_name (str): The human-readable tactic name (e.g., 'Defense Evasion').
        techniques (list[dict]): List of technique dicts associated with the tactic.
        
    Returns:
        list[tuple[str, str, list[dict], str]]: A list of tuples, each containing:
            - col_key (str): Unique internal key for the column (e.g., 'defense-evasion_0').
            - display_label (str): Display label for the column header (e.g., 'Defense Evasion').
            - techniques (list[dict]): List of technique dicts for this sub-column.
            - parent_tactic (str): The shortname used for grouping in build_header_spans.
    """
    n = len(techniques)
    if n <= MAX_ROWS_PER_COL:
        return [(shortname, display_name, techniques, shortname)]
    
    n_cols = (n + MAX_ROWS_PER_COL - 1) // MAX_ROWS_PER_COL
    result = []
    
    for i in range(n_cols):
        start = i * MAX_ROWS_PER_COL
        end = start + MAX_ROWS_PER_COL
        chunk = techniques[start:end]
        
        col_key = f"{shortname}_{i}"

        result.append((col_key, display_name, chunk, shortname))
        
    return result

def build_columns(tactic_order, tactic_map):
    """Apply split_tactic to each tactic in canonical order.
    
    Args:
        tactic_order (list[str]): The canonical order of tactic shortnames.
        tactic_map (dict[str, list[dict]]): A mapping from tactic shortname to techniques.
            
    Returns:
        list[tuple[str, str, list[dict], str]]: A list of column tuples, each containing:
            - col_key (str): Unique internal key for the column.
            - display_label (str): Display label for the column header.
            - techniques (list[dict]): List of technique dicts for this column.
            - parent_tactic (str): The tactic shortname used for grouping.
    """
    columns = []
    
    for shortname in tactic_order:
        if shortname not in tactic_map:
            continue
        
        techniques = tactic_map[shortname]
        display_name = shortname.replace("-", " ").title()
        sub_columns = split_tactic(shortname, display_name, techniques)
        columns.extend(sub_columns)
    
    return columns

def build_header_spans(columns):
    """Regroup consecutive columns sharing the same parent tactic into a single header span.
    
    Args:
        columns (list[tuple]): List of column tuples as returned by build_columns.
        
    Returns:
        list[tuple[int, int, str]]: A list of header span tuples, each containing:
            - col_start (int): The starting column index of the span.
            - col_end (int): The ending column index (exclusive).
            - display_label (str): The display name of the tactic for this span.
    """
    if not columns:
        return []
    
    header_spans = []
    current_start = 0
    current_base  = columns[0][3]
    current_label = columns[0][1]

    for col_i in range(1, len(columns)):
        base = columns[col_i][3]
        if base != current_base:
            header_spans.append((current_start, col_i, current_label))
            current_start = col_i
            current_base  = base
            current_label = columns[col_i][1]

    header_spans.append((current_start, len(columns), current_label))
    return header_spans


# --- Colormap ------------------------------------------------------------------

def build_cmap():
    return LinearSegmentedColormap.from_list(
        'att&ck', ['#f5f5f5', '#ffcccc', '#ff6666', '#cc0000'], N=256
    )


# --- Rendering (PNG, SVG, PDF) -------------------------------------------------

def render_heatmap(columns, header_spans, title, output_path, output_format):
    """Generate static heatmap using matplotlib.
    
    Args:
        columns (list[tuple]): List of column tuples as returned by build_columns.
        header_spans (list[tuple]): List of header span tuples as returned by build_header_spans.
        title (str): Title to display on the heatmap.
        output_path (str): Path to save the generated file.
        output_format (str): Format of the output file ('png', 'svg', or 'pdf').

    Returns:
        None
    """
    cmap = build_cmap()

    N_COLS = len(columns)
    MAX_ROWS = max((len(techniques) for _, _, techniques, _ in columns), default=0)

    fig_w = N_COLS * CELL_W + 0.3
    fig_h = MAX_ROWS * CELL_H + HEADER_H + TITLE_H + CBAR_H

    fig = plt.figure(figsize=(fig_w, fig_h))
    ax = fig.add_axes([0, CBAR_H / fig_h, 1, (MAX_ROWS * CELL_H + HEADER_H) / fig_h])
    ax.set_xlim(0, N_COLS * CELL_W)
    ax.set_ylim(0, MAX_ROWS * CELL_H + HEADER_H)
    ax.axis('off')
    fig.patch.set_facecolor('#12122a')
    ax.set_facecolor('#12122a')

    # --- Header spans ---
    for c_start, c_end, label in header_spans:
        x_left = c_start * CELL_W
        x_right = c_end * CELL_W
        width = x_right - x_left
        
        rect = mpatches.FancyBboxPatch(
            (x_left, MAX_ROWS * CELL_H),
            width, HEADER_H,
            boxstyle="round,pad=0.02,rounding_size=0.08",
            facecolor='#2a2a4a', edgecolor='#444466', linewidth=1.2
        )
        ax.add_patch(rect)
        
        ax.text(
            x_left + width / 2,
            MAX_ROWS * CELL_H + HEADER_H / 2,
            label,
            ha='center', va='center',
            fontsize=7.5, fontweight='bold', color='#ccccdd'
        )

    # --- Technique cells ---
    for col_i, (_, _, techs, _) in enumerate(columns):
        for row_i, tech in enumerate(techs):
            score = tech['score']
            name  = tech['name']
            tid   = tech['id']
            
            x = col_i * CELL_W
            y = (MAX_ROWS - 1 - row_i) * CELL_H
            
            color = cmap(score / 100.0)
            
            rect = mpatches.FancyBboxPatch(
                (x + PAD, y + PAD),
                CELL_W - 2 * PAD, CELL_H - 2 * PAD,
                boxstyle="round,pad=0.01,rounding_size=0.06",
                facecolor=color, edgecolor='#333355', linewidth=0.6
            )
            ax.add_patch(rect)
            
            # --- Name of the technique ---
            ax.text(
                x + CELL_W / 2,
                y + CELL_H / 2 + 0.08,
                truncate_name(name),
                ha='center', va='center',
                fontsize=5.5, color='#111111',
                fontweight='medium'
            )
            
            # --- ID of the technique ---
            ax.text(
                x + CELL_W / 2,
                y + CELL_H / 2 - 0.22,
                tid,
                ha='center', va='center',
                fontsize=4.5, color='#111111'
            )

    # --- Vertical dashed lines between different tactics ---
    for col_i in range(1, N_COLS):
        prev_base = columns[col_i - 1][3]
        curr_base = columns[col_i][3]
        if prev_base != curr_base:
            x = col_i * CELL_W
            ax.plot(
                [x, x],
                [0, MAX_ROWS * CELL_H],
                color='#555577', linewidth=0.8, linestyle='--', alpha=0.6
            )

    # --- Title and subtitle ---
    fig.text(
        0.5, 1 - 0.04 / fig_h, title,
        ha='center', va='top',
        fontsize=11, fontweight='bold', color='white'
    )
    fig.text(
        0.5, 1 - 0.26 / fig_h,
        'MITRE ATT&CK Enterprise v19  ·  Heatmap by technique score',
        ha='center', va='top',
        fontsize=7.5, color='#9999bb'
    )

    # --- Colorbar ---
    cbar_ax = fig.add_axes([0.12, 0.02, 0.76, 0.022])
    sm = plt.cm.ScalarMappable(cmap=cmap, norm=plt.Normalize(0, 100))
    sm.set_array([])
    cbar = fig.colorbar(sm, cax=cbar_ax, orientation='horizontal')
    cbar.set_label(
        'Score  (0 = not observed / inferred   100 = confirmed)',
        color='#aaaacc', fontsize=6.5, labelpad=3
    )
    cbar.ax.xaxis.set_tick_params(
        color='#777799', labelsize=5.5, labelcolor='#aaaacc'
    )

    dpi = 185 if output_format == 'png' else None
    fig.savefig(output_path, format=output_format, dpi=dpi, bbox_inches='tight',
                facecolor='#12122a', edgecolor='none')
    plt.close(fig)
    print(f"[+] Heatmap saved → {output_path}")


# --- Entrypoint ----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='ATT&CK Navigator layer to heatmap (png/svg/pdf)')
    parser.add_argument('--layer',  required=True, help='Path to ATT&CK Navigator JSON layer')
    parser.add_argument('--stix',   required=True, help='Path to Enterprise ATT&CK STIX bundle')
    parser.add_argument('--output', required=True, help='Output base path (extension ignored, derived from --format)')
    parser.add_argument('--title',  default=None,  help='Title displayed on the heatmap (default: layer name)')
    parser.add_argument('--format', choices=['png', 'svg', 'pdf', 'all'], default='png',
                        help='Output format (default: png)')
    parser.add_argument('--min-score', type=int, default=0, help='Minimum score to include a technique (default: 0)')
    args = parser.parse_args()

    min_score = args.min_score
    if min_score < 0 or min_score > 100:
        print("[!] Invalid --min-score value. Must be between 0 and 100.")
        return

    attack = load_attack_data(args.stix)
    tactic_order = get_tactic_order(attack)
    layer = load_layer(args.layer)
    title = args.title if args.title is not None else layer['name']
    tactic_map = enrich_layer(layer, attack, min_score)

    columns = build_columns(tactic_order, tactic_map)
    if not columns:
        submitted = {t['techniqueID'] for t in layer.get('techniques', [])}
        print("[!] No techniques matched any known tactic.")
        print(f"    Submitted IDs     : {', '.join(sorted(submitted))}")
        print(f"    ATT&CK version    : {layer.get('versions', {}).get('attack', 'unknown')}")
        return

    header_spans = build_header_spans(columns)

    formats = ['png', 'svg', 'pdf'] if args.format == 'all' else [args.format]
    
    for output_format in formats:
        base_path, ext = os.path.splitext(args.output)
        base_path = base_path if ext else args.output
        output_path = f"{base_path}.{output_format}"
        render_heatmap(columns, header_spans, title, output_path, output_format)


if __name__ == '__main__':
    main()