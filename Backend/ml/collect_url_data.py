import argparse
import csv
import json
from pathlib import Path
from urllib.parse import urlparse


def is_http_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")


def normalize_url(raw: str) -> str:
    candidate = (raw or "").strip()
    if not candidate:
        return ""

    if not is_http_url(candidate):
        candidate = f"http://{candidate}"

    parsed = urlparse(candidate)
    if not parsed.netloc:
        return ""

    return candidate


def read_txt_urls(file_path: Path) -> list[str]:
    rows: list[str] = []
    for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append(line)
    return rows


def pick_column(fieldnames: list[str], candidates: list[str], explicit: str | None) -> str | None:
    if explicit and explicit in fieldnames:
        return explicit

    if explicit and explicit.isdigit():
        idx = int(explicit)
        if 0 <= idx < len(fieldnames):
            return fieldnames[idx]

    for candidate in candidates:
        if candidate in fieldnames:
            return candidate

    return None


def parse_label(value: str) -> int:
    val = (value or "").strip().lower()
    if val in {"1", "true", "phishing", "malicious", "bad"}:
        return 1
    if val in {"0", "false", "benign", "safe", "ham", "legitimate"}:
        return 0
    return int(float(val))


def read_csv_urls_fixed_label(file_path: Path, url_column: str | None, has_header: bool = True) -> list[str]:
    with file_path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
        if has_header:
            reader = csv.DictReader(handle)
            fieldnames = reader.fieldnames or []
            url_col = pick_column(fieldnames, ["url", "URL", "link", "domain"], url_column)
            if not url_col:
                raise ValueError(f"Could not find URL column in {file_path.name}. Columns: {fieldnames}")

            values: list[str] = []
            for row in reader:
                value = (row.get(url_col) or "").strip()
                if value:
                    values.append(value)
        else:
            # No header - use column index
            reader = csv.reader(handle)
            try:
                col_idx = int(url_column) if url_column else 0
            except (ValueError, TypeError):
                col_idx = 0
            
            values: list[str] = []
            for row in reader:
                if len(row) > col_idx:
                    value = row[col_idx].strip()
                    if value:
                        values.append(value)
        return values


def read_csv_urls_with_labels(file_path: Path, url_column: str | None, label_column: str | None, flip_labels: bool = False) -> list[tuple[str, int]]:
    with file_path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []

        url_col = pick_column(fieldnames, ["url", "URL", "link", "domain"], url_column)
        label_col = pick_column(fieldnames, ["label", "Label", "target", "class"], label_column)

        if not url_col or not label_col:
            raise ValueError(
                f"Need URL and label columns in {file_path.name}. Columns: {fieldnames}"
            )

        rows: list[tuple[str, int]] = []
        for row in reader:
            raw_url = (row.get(url_col) or "").strip()
            raw_label = (row.get(label_col) or "").strip()
            if not raw_url or not raw_label:
                continue
            try:
                label = parse_label(raw_label)
            except Exception:
                continue
            if label in {0, 1}:
                # Flip labels if needed (some datasets use 1=benign, 0=phishing)
                if flip_labels:
                    label = 1 - label
                rows.append((raw_url, label))
        return rows


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def collect(config_path: Path, output_path: Path, max_per_source: int | None = None) -> None:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    sources = config.get("url_sources", [])
    if not sources:
        raise ValueError("No url_sources found in config")

    backend_root = Path(__file__).resolve().parent.parent
    records: list[dict[str, str | int]] = []

    for source in sources:
        name = source["name"]
        source_type = source.get("type", "txt")
        source_path = source["path_or_url"]
        url_column = source.get("url_column")
        label_column = source.get("label_column")
        fixed_label = source.get("label")
        flip_labels = source.get("flip_labels", False)
        has_header = source.get("has_header", True)
        if source_path.startswith("http://") or source_path.startswith("https://"):
            print(f"[SKIP] {name}: remote URL source is disabled in this local-first script")
            continue

        local_file = (backend_root / source_path).resolve()
        if not local_file.exists():
            print(f"[SKIP] {name}: file missing -> {local_file}")
            continue

        accepted = 0

        try:
            if source_type == "txt":
                if fixed_label is None:
                    raise ValueError("TXT source needs fixed 'label'")
                for raw in read_txt_urls(local_file):
                    normalized = normalize_url(raw)
                    if not normalized:
                        continue
                    records.append({"url": normalized, "label": int(fixed_label), "source": name})
                    accepted += 1
                    if max_per_source and accepted >= max_per_source:
                        break

            elif source_type == "csv":
                if label_column:
                    for raw_url, row_label in read_csv_urls_with_labels(local_file, url_column, label_column, flip_labels):
                        normalized = normalize_url(raw_url)
                        if not normalized:
                            continue
                        records.append({"url": normalized, "label": int(row_label), "source": name})
                        accepted += 1
                        if max_per_source and accepted >= max_per_source:
                            break
                else:
                    if fixed_label is None:
                        raise ValueError("CSV source needs either fixed 'label' or 'label_column'")
                    for raw in read_csv_urls_fixed_label(local_file, url_column, has_header):
                        normalized = normalize_url(raw)
                        if not normalized:
                            continue
                        records.append({"url": normalized, "label": int(fixed_label), "source": name})
                        accepted += 1
                        if max_per_source and accepted >= max_per_source:
                            break
            else:
                raise ValueError(f"Unsupported source type: {source_type}")

            print(f"[OK] {name}: {accepted} URLs")

        except Exception as exc:
            print(f"[ERROR] {name}: {exc}")

    if not records:
        raise RuntimeError("No data collected. Check config and files.")

    deduped: list[dict[str, str | int]] = []
    seen: set[tuple[str, int]] = set()
    for item in records:
        key = (str(item["url"]), int(item["label"]))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    ensure_dir(output_path.parent)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["url", "label", "source"])
        writer.writeheader()
        writer.writerows(deduped)

    positives = sum(1 for row in deduped if int(row["label"]) == 1)
    negatives = sum(1 for row in deduped if int(row["label"]) == 0)

    print("\n=== URL DATASET READY ===")
    print(f"Output: {output_path}")
    print(f"Total: {len(deduped)}")
    print(f"Phishing (1): {positives}")
    print(f"Benign (0): {negatives}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect URL dataset for training")
    parser.add_argument("--sources", default="ml/data_sources.example.json")
    parser.add_argument("--output", default="ml/datasets/processed/url_dataset.csv")
    parser.add_argument("--max-per-source", type=int, default=None)
    args = parser.parse_args()

    backend_root = Path(__file__).resolve().parent.parent
    config_path = (backend_root / args.sources).resolve()
    output_path = (backend_root / args.output).resolve()

    collect(config_path=config_path, output_path=output_path, max_per_source=args.max_per_source)


if __name__ == "__main__":
    main()
