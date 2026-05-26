import json
import os
import sys
import csv
import subprocess
import re
import threading
import queue
import tkinter as tk
from tkinter import filedialog, messagebox
import tkinter.ttk as ttk
from datetime import date

# -----------------------------------------------------------
#   БАЗОВЫЕ ДИРЕКТОРИИ (для exe и для .py)
# -----------------------------------------------------------

if getattr(sys, "frozen", False) and hasattr(sys, "executable"):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DEFAULT_REPORTS_DIR = os.path.join(BASE_DIR, "Reports")
DEFAULT_ANALYZED_DIR = os.path.join(BASE_DIR, "Analyzed")

os.makedirs(DEFAULT_REPORTS_DIR, exist_ok=True)
os.makedirs(DEFAULT_ANALYZED_DIR, exist_ok=True)

if os.name == "nt":
    try:
        CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW
    except AttributeError:
        CREATE_NO_WINDOW = 0
else:
    CREATE_NO_WINDOW = 0

# -----------------------------------------------------------
#   ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# -----------------------------------------------------------

def normalize_path(path: str) -> str:
    if not path:
        return ""
    path = path.strip()
    if len(path) >= 2 and path[0] == path[-1] and path[0] in ('"', "'"):
        path = path[1:-1]
    return path


def extract_content_from_path(path: str) -> str:
    if not path:
        return ""
    match = re.search(r"LOC-[A-Z]{2}-\d+", path)
    return match.group(0) if match else ""


def get_content_type(content_id: str) -> str:
    if not content_id:
        return ""
    parts = content_id.split("-")
    return parts[1] if len(parts) >= 3 else ""


def extract_date_from_content_dir(content_dir: str) -> str:
    base = os.path.basename(os.path.normpath(content_dir))
    m = re.search(r"(\d{4}_\d{2}_\d{2})", base)
    if m:
        return m.group(1)
    return date.today().strftime("%Y_%m_%d")


def get_content_prefix(content_dir: str) -> str:
    """
    Префикс для имён файлов по имени каталога с контентом.
    knowledgebase_2025_12_03 -> knowledgebase
    если даты нет -> весь basename.
    """
    base = os.path.basename(os.path.normpath(content_dir)) or "content"
    m = re.search(r"(\d{4}_\d{2}_\d{2})", base)
    if m:
        prefix = base[:m.start()].rstrip("_- ")
        if not prefix:
            prefix = base
    else:
        prefix = base
    return prefix


def _extract_package_name(pkg_data):
    name_field = pkg_data.get("Name")
    if isinstance(name_field, list):
        ru_items = [x for x in name_field if isinstance(x, dict) and x.get("Locale") == "ru"]
        if ru_items:
            return ru_items[0].get("Text", "") or ""
        first = name_field[0]
        if isinstance(first, dict):
            return first.get("Text", "") or ""
    elif isinstance(name_field, str):
        return name_field
    return ""


IGNORE_SEGMENTS_LOWER = {
    "correlation_rules",
    "correlations_rules",
    "correlation",
    "correlations",
    "normalization_rules",
    "normalization",
    "normalizations",
    "enrichment_rules",
    "enrichment",
    "table_lists",
    "tables",
    "rules_filters",
    "rules_filters_tag",
    "rules",
    "origins",
    "normalization_formulas",
    "correlations_formulas",
    "correlation_formulas",
}

GENERIC_SEGMENTS_LOWER = {"common", "global", "shared"}

SINK_SEGMENTS_LOWER = {"syslog", "journal", "journald", "events", "event", "logs", "log"}


def clean_source_path(path: str) -> str:
    if not path:
        return ""
    parts = [p for p in path.split("/") if p]
    cleaned = []
    for p in parts:
        if p.lower() in IGNORE_SEGMENTS_LOWER:
            continue
        cleaned.append(p)
    return "/".join(cleaned)


def is_service_segment(seg: str) -> bool:
    if not seg:
        return False
    s = seg.lower()
    if s in IGNORE_SEGMENTS_LOWER:
        return True
    return ("correlat" in s) or ("normaliz" in s) or ("enrich" in s)


def is_sink_segment(seg: str) -> bool:
    if not seg:
        return False
    s = seg.lower()
    if s in SINK_SEGMENTS_LOWER:
        return True
    if "syslog" in s:
        return True
    return False


def compute_source_platform(source_name: str, content_name: str) -> str:
    candidate = ""

    if source_name:
        parts = [p for p in source_name.split("/") if p]
        if parts:
            if len(parts) == 2 and is_service_segment(parts[1]):
                candidate = parts[0]
            else:
                filtered = [p for p in parts if p.lower() not in GENERIC_SEGMENTS_LOWER]
                while filtered and is_sink_segment(filtered[-1]):
                    filtered.pop()
                if filtered:
                    candidate = filtered[-1]

    if not candidate and content_name and content_name.startswith("TI_"):
        tail = content_name[3:]
        token = tail.split("_", 1)[0]
        candidate = token

    return candidate


def _walk_package_items(node, package_full_name, source_name, meta):
    if not isinstance(node, dict):
        return

    node_id = node.get("Id")
    node_name = node.get("Name")
    node_kind = node.get("Kind")

    current_source = source_name

    if node_name and not node_id and not node_kind:
        if source_name:
            current_source = f"{source_name}/{node_name}"
        else:
            current_source = node_name

    if isinstance(node_id, str) and node_id.startswith("LOC-") and node_name and node_kind:
        cleaned = clean_source_path(current_source)
        meta[node_id] = {
            "package_id": package_full_name,
            "content_name": node_name,
            "source_name": cleaned,
        }

    items = node.get("Items", [])
    if isinstance(items, list):
        for child in items:
            _walk_package_items(child, package_full_name, current_source, meta)


def build_content_metadata_from_packages(content_dir: str):
    packages_dir = os.path.join(content_dir, "packages")
    meta = {}

    if not os.path.isdir(packages_dir):
        return meta

    for entry in os.scandir(packages_dir):
        if not entry.is_dir():
            continue

        spec_path = os.path.join(entry.path, "package.spec")
        if not os.path.isfile(spec_path):
            continue

        try:
            with open(spec_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        pkg_id = data.get("Id", entry.name)
        pkg_name = _extract_package_name(data)
        if pkg_name:
            package_full_name = f"{pkg_id}/{pkg_name}"
        else:
            package_full_name = pkg_id

        content_list = data.get("Content", [])
        if not isinstance(content_list, list):
            continue

        for content_block in content_list:
            if not isinstance(content_block, dict):
                continue
            source_name = content_block.get("Name", "") or ""
            items = content_block.get("Items", [])
            if isinstance(items, list):
                for node in items:
                    _walk_package_items(node, package_full_name, source_name, meta)

    return meta


def iter_rows_from_json(json_file: str, content_meta=None):
    with open(json_file, "r", encoding="utf-8") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError as e:
            print(f"Ошибка JSON в файле {json_file}: {e}")
            return

    if not isinstance(data, list):
        print(f"Предупреждение: в файле {json_file} корневой элемент не список. Пропуск.")
        return

    for item in data:
        if not isinstance(item, dict):
            continue

        description = item.get("description", "")
        check_name = item.get("check_name", "")
        severity = item.get("severity", "")

        location = item.get("location", {}) or {}
        path = location.get("path", "")
        lines = location.get("lines", {}) or {}
        line_begin = lines.get("begin", "")
        line_end = lines.get("end", "")

        content_id = extract_content_from_path(path)
        content_type = get_content_type(content_id)

        packet_id = ""
        content_name = ""
        source_name = ""

        if content_meta and content_id:
            meta = content_meta.get(content_id)
            if meta:
                packet_id = meta.get("package_id", "") or ""
                content_name = meta.get("content_name", "") or ""
                source_name = meta.get("source_name", "") or ""

        source_platform = compute_source_platform(source_name, content_name)

        yield {
            "Packet_ID": packet_id,
            "Content_ID": content_id,
            "Content_name": content_name,
            "Content_type": content_type,
            "Source_name": source_platform,
            "Source_platform": source_name,
            "Severity": severity,
            "Description": description,
            "line_begin": line_begin,
            "line_end": line_end,
            "Validator": check_name,
        }


def write_json_to_csv(json_file_path: str, csv_file_path: str, content_meta=None) -> int:
    fieldnames = [
        "Packet_ID",
        "Content_ID",
        "Content_name",
        "Content_type",
        "Source_name",
        "Source_platform",
        "Severity",
        "Description",
        "line_begin",
        "line_end",
        "Validator",
    ]

    written = 0
    seen = set()

    rows_iter = iter_rows_from_json(json_file_path, content_meta=content_meta)

    with open(csv_file_path, "w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()

        if rows_iter is not None:
            for row in rows_iter:
                key = (row.get("Content_ID"), row.get("Severity"), row.get("Description"))
                if key in seen:
                    continue
                seen.add(key)

                writer.writerow(row)
                written += 1

    return written


def process_single_file(json_file_path: str, csv_file_path: str, content_meta=None):
    if not os.path.isfile(json_file_path):
        raise FileNotFoundError(f"Файл '{json_file_path}' не найден или не является файлом.")

    written = write_json_to_csv(json_file_path, csv_file_path, content_meta=content_meta)
    if written == 0:
        raise ValueError("Не удалось извлечь данные из файла (0 строк).")


def process_directory(json_dir_path: str, output_dir_path: str, content_meta=None) -> int:
    if not os.path.isdir(json_dir_path):
        raise NotADirectoryError(f"'{json_dir_path}' не является директорией.")

    os.makedirs(output_dir_path, exist_ok=True)

    processed_files = 0
    for entry in os.scandir(json_dir_path):
        if not entry.is_file():
            continue
        if not entry.name.lower().endswith(".json"):
            continue

        json_file_path = entry.path
        base_name, _ = os.path.splitext(entry.name)
        csv_file_name = base_name + ".csv"
        csv_file_path = os.path.join(output_dir_path, csv_file_name)

        written = write_json_to_csv(json_file_path, csv_file_path, content_meta=content_meta)
        if written > 0:
            processed_files += 1
        else:
            try:
                os.remove(csv_file_path)
            except OSError:
                pass

    return processed_files


def run_linter_for_severities(
    program_dir: str,
    content_dir: str,
    reports_json_dir: str,
    log_func=print,
    progress_callback=None,
) -> int:
    exe_path = os.path.join(program_dir, "xp-sdk", "cli", "evt-xp-linter.exe")
    if not os.path.isfile(exe_path):
        raise FileNotFoundError(f"Не найден исполняемый файл linter: {exe_path}")

    taxonomy_path = os.path.join(content_dir, "taxonomy", "taxonomy.json")
    if not os.path.isfile(taxonomy_path):
        raise FileNotFoundError(f"Не найден taxonomy.json по пути: {taxonomy_path}")

    os.makedirs(reports_json_dir, exist_ok=True)

    date_str = extract_date_from_content_dir(content_dir)
    prefix = get_content_prefix(content_dir)

    severities = ["critical", "error", "suggestion", "warning"]
    success_count = 0

    for sev in severities:
        json_report = os.path.join(reports_json_dir, f"{prefix}_{sev}_{date_str}.json")
        cmd = [
            exe_path,
            content_dir,
            "--print-validators",
            "-t",
            taxonomy_path,
            "--minimal-severity",
            sev,
            "--code-quality",
            json_report,
        ]
        log_func(f"Запуск: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            creationflags=CREATE_NO_WINDOW,
        )
        if result.stdout:
            log_func(f"[{sev}] stdout:\n{result.stdout}")
        if result.stderr:
            log_func(f"[{sev}] stderr:\n{result.stderr}")
        if result.returncode != 0:
            log_func(f"[{sev}] ВНИМАНИЕ: команда завершилась с кодом {result.returncode}. Продолжаем.")
        else:
            success_count += 1

        if progress_callback is not None:
            progress_callback()

    return success_count


def convert_reports_to_named_csvs(content_dir: str, reports_json_dir: str, csv_out_dir: str, content_meta=None) -> int:
    """
    Для режима 'Проверка контента':
    JSON: <prefix>_<severity>_YYYY_MM_DD.json
    CSV:  <prefix>_<severity>_YYYY_MM_DD.csv
    где prefix зависит от имени каталога с контентом.
    """
    os.makedirs(csv_out_dir, exist_ok=True)

    date_str = extract_date_from_content_dir(content_dir)
    prefix = get_content_prefix(content_dir)

    severities = ["critical", "error", "suggestion", "warning"]
    created = 0

    for sev in severities:
        json_path = os.path.join(reports_json_dir, f"{prefix}_{sev}_{date_str}.json")
        if not os.path.isfile(json_path):
            continue

        csv_name = f"{prefix}_{sev}_{date_str}.csv"
        csv_path = os.path.join(csv_out_dir, csv_name)

        written = write_json_to_csv(json_path, csv_path, content_meta=content_meta)
        if written > 0:
            created += 1
        else:
            try:
                os.remove(csv_path)
            except OSError:
                pass

    return created


# -----------------------------------------------------------
#   GUI (тёмная тема, more modern)
# -----------------------------------------------------------

class JsonToCsvApp:
    def __init__(self, master: tk.Tk):
        self.master = master
        master.title("Content Validator")

        BG_MAIN = "#111827"
        BG_FRAME = "#1f2937"
        BG_ENTRY = "#111827"
        FG_TEXT = "#e5e7eb"
        FG_SUBTEXT = "#9ca3af"
        ACCENT = "#3b82f6"
        ACCENT_DARK = "#2563eb"
        BORDER = "#374151"

        master.configure(bg=BG_MAIN)
        master.minsize(820, 560)

        style = ttk.Style()
        for theme in ("clam", "vista", "xpnative"):
            try:
                style.theme_use(theme)
                break
            except tk.TclError:
                continue

        style.configure(".", background=BG_MAIN, foreground=FG_TEXT, fieldbackground=BG_ENTRY)

        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground=FG_TEXT, background=BG_MAIN)
        style.configure("SubHeader.TLabel", font=("Segoe UI", 9), foreground=FG_SUBTEXT, background=BG_MAIN)

        style.configure("Card.TFrame", background=BG_FRAME, bordercolor=BORDER, relief="flat")
        style.configure("Card.TLabelframe", background=BG_FRAME, bordercolor=BORDER, relief="flat")
        style.configure("Card.TLabelframe.Label", background=BG_FRAME, foreground=FG_TEXT, font=("Segoe UI", 9, "bold"))

        style.configure("TLabel", background=BG_FRAME, foreground=FG_TEXT, font=("Segoe UI", 9))
        style.configure("TEntry", fieldbackground=BG_ENTRY, foreground=FG_TEXT, bordercolor=BORDER)

        style.configure(
            "TRadiobutton",
            background=BG_FRAME,
            foreground=FG_TEXT,
            focuscolor=BG_FRAME
        )
        style.map(
            "TRadiobutton",
            background=[("active", BG_FRAME), ("pressed", BG_FRAME), ("hover", BG_FRAME)],
            foreground=[("active", FG_TEXT), ("hover", FG_TEXT)]
        )

        style.configure("Accent.TButton",
                        background=ACCENT,
                        foreground="#ffffff",
                        borderwidth=0,
                        focusthickness=0,
                        padding=(10, 5),
                        font=("Segoe UI", 9, "bold"))
        style.map("Accent.TButton",
                  background=[("active", ACCENT_DARK), ("pressed", ACCENT_DARK)],
                  foreground=[("disabled", "#9ca3af")])

        style.configure("TButton",
                        background="#4b5563",
                        foreground=FG_TEXT,
                        borderwidth=0,
                        focusthickness=0,
                        padding=(8, 4),
                        font=("Segoe UI", 9))
        style.map("TButton",
                  background=[("active", "#6b7280"), ("pressed", "#6b7280")])

        style.configure("blue.Horizontal.TProgressbar",
                        troughcolor=BG_FRAME,
                        bordercolor=BG_FRAME,
                        background=ACCENT,
                        lightcolor=ACCENT,
                        darkcolor=ACCENT_DARK)

        container = ttk.Frame(master, style="Card.TFrame", padding=(12, 10))
        container.pack(fill="both", expand=True, padx=10, pady=10)

        header_frame = ttk.Frame(container, style="Card.TFrame")
        header_frame.pack(fill="x")

        ttk.Label(
            header_frame,
            text="Content Validator",
            style="Header.TLabel"
        ).pack(anchor="w")

        ttk.Label(
            header_frame,
            text="Проверка контента XP Linter и парсинг отчётов JSON → CSV",
            style="SubHeader.TLabel"
        ).pack(anchor="w", pady=(2, 6))

        modes_frame = ttk.LabelFrame(container, text="Режим работы", style="Card.TLabelframe", padding=(10, 6))
        modes_frame.pack(fill="x", pady=(4, 6))

        self.mode_var = tk.StringVar(value="file")
        self.is_running = False
        self.ui_queue = queue.Queue()

        ttk.Radiobutton(
            modes_frame, text="Один JSON файл",
            variable=self.mode_var, value="file",
            command=self.update_mode
        ).pack(side="left", padx=(0, 14))

        ttk.Radiobutton(
            modes_frame, text="Директория JSON файлов",
            variable=self.mode_var, value="dir",
            command=self.update_mode
        ).pack(side="left", padx=(0, 14))

        ttk.Radiobutton(
            modes_frame, text="Проверка контента (XP Linter)",
            variable=self.mode_var, value="check",
            command=self.update_mode
        ).pack(side="left", padx=(0, 14))

        self.paths_frame = ttk.LabelFrame(container, text="Пути", style="Card.TLabelframe", padding=(10, 8))
        self.paths_frame.pack(fill="x", pady=(4, 6))

        self.lbl_json_file = ttk.Label(self.paths_frame, text="JSON файл:")
        self.entry_json_file = ttk.Entry(self.paths_frame, width=70)
        self.btn_json_file = ttk.Button(self.paths_frame, text="Обзор...", command=self.browse_json_file)

        self.lbl_csv_file = ttk.Label(self.paths_frame, text="CSV файл (выход):")
        self.entry_csv_file = ttk.Entry(self.paths_frame, width=70)
        self.btn_csv_file = ttk.Button(self.paths_frame, text="Обзор...", command=self.browse_csv_file)

        self.lbl_json_dir = ttk.Label(self.paths_frame, text="Директория JSON:")
        self.entry_json_dir = ttk.Entry(self.paths_frame, width=70)
        self.btn_json_dir = ttk.Button(self.paths_frame, text="Обзор...", command=self.browse_json_dir)

        self.lbl_output_dir = ttk.Label(self.paths_frame, text="Директория CSV (выход):")
        self.entry_output_dir = ttk.Entry(self.paths_frame, width=70)
        self.btn_output_dir = ttk.Button(self.paths_frame, text="Обзор...", command=self.browse_output_dir)

        self.lbl_prog_dir = ttk.Label(self.paths_frame, text="Директория с программой:")
        self.entry_prog_dir = ttk.Entry(self.paths_frame, width=70)
        self.btn_prog_dir = ttk.Button(self.paths_frame, text="Обзор...", command=self.browse_prog_dir)

        self.lbl_content_dir = ttk.Label(self.paths_frame, text="Директория с контентом:")
        self.entry_content_dir = ttk.Entry(self.paths_frame, width=70)
        self.btn_content_dir = ttk.Button(self.paths_frame, text="Обзор...", command=self.browse_content_dir)

        self.lbl_reports_json_dir = ttk.Label(self.paths_frame, text="Директория JSON отчётов:")
        self.entry_reports_json_dir = ttk.Entry(self.paths_frame, width=70)
        self.btn_reports_json_dir = ttk.Button(self.paths_frame, text="Обзор...", command=self.browse_reports_json_dir)

        bottom_frame = ttk.Frame(container, style="Card.TFrame")
        bottom_frame.pack(fill="x", pady=(2, 4))

        self.run_button = ttk.Button(bottom_frame, text="Запустить обработку", style="Accent.TButton",
                                     command=self.run_processing)
        self.run_button.pack(side="left", pady=4)

        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(
            bottom_frame,
            variable=self.progress_var,
            maximum=100,
            style="blue.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(side="right", fill="x", expand=True, padx=(12, 0), pady=6)

        self.log_frame = ttk.LabelFrame(container, text="Лог", style="Card.TLabelframe", padding=(8, 6))
        self.log_frame.pack(fill="both", expand=True, pady=(4, 0))

        log_container = ttk.Frame(self.log_frame, style="Card.TFrame")
        log_container.pack(fill="both", expand=True)

        self.text_log = tk.Text(
            log_container,
            height=15,
            state="disabled",
            wrap="none",
            bg="#020617",
            fg=FG_TEXT,
            insertbackground=FG_TEXT,
            relief="flat",
            borderwidth=0
        )
        self.text_log.configure(font=("Consolas", 9))
        self.text_log.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(log_container, orient="vertical", command=self.text_log.yview)
        self.text_log.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        self.update_mode()
        self.paths_frame.columnconfigure(1, weight=1)

        self.master.after(100, self.process_ui_queue)

    # ---------------- UI queue ----------------

    def enqueue(self, kind, payload=None):
        self.ui_queue.put((kind, payload))

    def process_ui_queue(self):
        while True:
            try:
                kind, payload = self.ui_queue.get_nowait()
            except queue.Empty:
                break

            if kind == "log":
                self._log_direct(payload)
            elif kind == "progress_reset":
                self._reset_progress_direct()
            elif kind == "progress_add":
                self._add_progress_direct(payload)
            elif kind == "running":
                self._set_running_direct(bool(payload))
            elif kind == "message_info":
                title, text = payload
                messagebox.showinfo(title, text)
            elif kind == "message_error":
                title, text = payload
                messagebox.showerror(title, text)

        self.master.after(100, self.process_ui_queue)

    # ---------------- Лог ----------------

    def _log_direct(self, message: str):
        self.text_log.configure(state="normal")
        self.text_log.insert("end", message + "\n")
        self.text_log.see("end")
        self.text_log.configure(state="disabled")

    def log(self, message: str):
        self.enqueue("log", message)

    # ---------------- Прогресс ----------------

    def _reset_progress_direct(self):
        self.progress_var.set(0)
        self.master.update_idletasks()

    def _add_progress_direct(self, step):
        new_val = self.progress_var.get() + step
        if new_val > 100:
            new_val = 100
        self.progress_var.set(new_val)
        self.master.update_idletasks()

    def reset_progress(self):
        self.enqueue("progress_reset")

    def add_progress(self, step):
        self.enqueue("progress_add", step)

    # ---------------- Статус ----------------

    def _set_running_direct(self, running: bool):
        self.is_running = running
        if running:
            self.run_button.configure(state="disabled", text="Выполняется...")
        else:
            self.run_button.configure(state="normal", text="Запустить обработку")
        self.master.update_idletasks()

    # ---------------- Размещение полей путей ----------------

    def clear_paths_grid(self):
        widgets = [
            self.lbl_json_file, self.entry_json_file, self.btn_json_file,
            self.lbl_csv_file, self.entry_csv_file, self.btn_csv_file,
            self.lbl_json_dir, self.entry_json_dir, self.btn_json_dir,
            self.lbl_output_dir, self.entry_output_dir, self.btn_output_dir,
            self.lbl_prog_dir, self.entry_prog_dir, self.btn_prog_dir,
            self.lbl_content_dir, self.entry_content_dir, self.btn_content_dir,
            self.lbl_reports_json_dir, self.entry_reports_json_dir, self.btn_reports_json_dir,
        ]
        for w in widgets:
            w.grid_forget()

    def update_mode(self):
        mode = self.mode_var.get()
        self.clear_paths_grid()

        if mode == "file":
            self.lbl_json_file.grid(row=0, column=0, sticky="e", padx=5, pady=4)
            self.entry_json_file.grid(row=0, column=1, padx=5, pady=4, sticky="we")
            self.btn_json_file.grid(row=0, column=2, padx=5, pady=4)

            self.lbl_csv_file.grid(row=1, column=0, sticky="e", padx=5, pady=4)
            self.entry_csv_file.grid(row=1, column=1, padx=5, pady=4, sticky="we")
            self.btn_csv_file.grid(row=1, column=2, padx=5, pady=4)

        elif mode == "dir":
            self.lbl_json_dir.grid(row=0, column=0, sticky="e", padx=5, pady=4)
            self.entry_json_dir.grid(row=0, column=1, padx=5, pady=4, sticky="we")
            self.btn_json_dir.grid(row=0, column=2, padx=5, pady=4)

            self.lbl_output_dir.grid(row=1, column=0, sticky="e", padx=5, pady=4)
            self.entry_output_dir.grid(row=1, column=1, padx=5, pady=4, sticky="we")
            self.btn_output_dir.grid(row=1, column=2, padx=5, pady=4)

        else:
            self.lbl_prog_dir.grid(row=0, column=0, sticky="e", padx=5, pady=4)
            self.entry_prog_dir.grid(row=0, column=1, padx=5, pady=4, sticky="we")
            self.btn_prog_dir.grid(row=0, column=2, padx=5, pady=4)

            self.lbl_content_dir.grid(row=1, column=0, sticky="e", padx=5, pady=4)
            self.entry_content_dir.grid(row=1, column=1, padx=5, pady=4, sticky="we")
            self.btn_content_dir.grid(row=1, column=2, padx=5, pady=4)

            self.lbl_reports_json_dir.grid(row=2, column=0, sticky="e", padx=5, pady=4)
            self.entry_reports_json_dir.grid(row=2, column=1, padx=5, pady=4, sticky="we")
            self.btn_reports_json_dir.grid(row=2, column=2, padx=5, pady=4)

            self.lbl_output_dir.grid(row=3, column=0, sticky="e", padx=5, pady=4)
            self.entry_output_dir.grid(row=3, column=1, padx=5, pady=4, sticky="we")
            self.btn_output_dir.grid(row=3, column=2, padx=5, pady=4)

            if not self.entry_reports_json_dir.get():
                self.entry_reports_json_dir.insert(0, DEFAULT_REPORTS_DIR)
            if not self.entry_output_dir.get():
                self.entry_output_dir.insert(0, DEFAULT_ANALYZED_DIR)

    # ---------------- Диалоги выбора путей ----------------

    def browse_json_file(self):
        filename = filedialog.askopenfilename(
            title="Выберите JSON файл",
            filetypes=[("JSON files", "*.json"), ("Все файлы", "*.*")]
        )
        if filename:
            self.entry_json_file.delete(0, tk.END)
            self.entry_json_file.insert(0, filename)

    def browse_csv_file(self):
        filename = filedialog.asksaveasfilename(
            title="Выберите CSV файл для сохранения",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Все файлы", "*.*")]
        )
        if filename:
            self.entry_csv_file.delete(0, tk.END)
            self.entry_csv_file.insert(0, filename)

    def browse_json_dir(self):
        dirname = filedialog.askdirectory(title="Выберите директорию с JSON файлами")
        if dirname:
            self.entry_json_dir.delete(0, tk.END)
            self.entry_json_dir.insert(0, dirname)

    def browse_output_dir(self):
        dirname = filedialog.askdirectory(title="Выберите директорию для CSV файлов")
        if dirname:
            self.entry_output_dir.delete(0, tk.END)
            self.entry_output_dir.insert(0, dirname)

    def browse_prog_dir(self):
        dirname = filedialog.askdirectory(title="Выберите директорию с программой (где лежит xp-sdk)")
        if dirname:
            self.entry_prog_dir.delete(0, tk.END)
            self.entry_prog_dir.insert(0, dirname)

    def browse_content_dir(self):
        dirname = filedialog.askdirectory(title="Выберите директорию с контентом (knowledgebase_...)")
        if dirname:
            self.entry_content_dir.delete(0, tk.END)
            self.entry_content_dir.insert(0, dirname)

    def browse_reports_json_dir(self):
        dirname = filedialog.askdirectory(title="Выберите директорию для JSON отчётов")
        if dirname:
            self.entry_reports_json_dir.delete(0, tk.END)
            self.entry_reports_json_dir.insert(0, dirname)

    # ---------------- Запуск обработки ----------------

    def run_processing(self):
        if self.is_running:
            return

        mode = self.mode_var.get()

        try:
            if mode == "file":
                json_file = normalize_path(self.entry_json_file.get().strip())
                csv_file = normalize_path(self.entry_csv_file.get().strip())

                if not json_file:
                    messagebox.showwarning("Ошибка", "Не указан путь к JSON файлу.")
                    return
                if not csv_file:
                    messagebox.showwarning("Ошибка", "Не указан путь к выходному CSV файлу.")
                    return

                params = {"mode": "file", "json_file": json_file, "csv_file": csv_file}

            elif mode == "dir":
                json_dir = normalize_path(self.entry_json_dir.get().strip())
                out_dir = normalize_path(self.entry_output_dir.get().strip())

                if not json_dir:
                    messagebox.showwarning("Ошибка", "Не указана директория с JSON файлами.")
                    return
                if not out_dir:
                    messagebox.showwarning("Ошибка", "Не указана директория для CSV файлов.")
                    return

                params = {"mode": "dir", "json_dir": json_dir, "out_dir": out_dir}

            else:
                prog_dir = normalize_path(self.entry_prog_dir.get().strip())
                content_dir = normalize_path(self.entry_content_dir.get().strip())
                reports_json_dir = normalize_path(self.entry_reports_json_dir.get().strip())
                csv_out_dir = normalize_path(self.entry_output_dir.get().strip())

                if not prog_dir:
                    messagebox.showwarning("Ошибка", "Не указана директория с программой.")
                    return
                if not content_dir:
                    messagebox.showwarning("Ошибка", "Не указана директория с контентом.")
                    return
                if not reports_json_dir:
                    messagebox.showwarning("Ошибка", "Не указана директория для JSON отчётов.")
                    return
                if not csv_out_dir:
                    messagebox.showwarning("Ошибка", "Не указана директория для CSV файлов.")
                    return

                params = {
                    "mode": "check",
                    "prog_dir": prog_dir,
                    "content_dir": content_dir,
                    "reports_json_dir": reports_json_dir,
                    "csv_out_dir": csv_out_dir,
                }

        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка при чтении путей:\n{e}")
            return

        self.enqueue("running", True)
        self.reset_progress()
        worker = threading.Thread(target=self.worker_thread, args=(params,), daemon=True)
        worker.start()

    # ---------------- Рабочий поток ----------------

    def worker_thread(self, params: dict):
        mode = params["mode"]
        try:
            if mode == "file":
                json_file = params["json_file"]
                csv_file = params["csv_file"]

                self.log(f"Обработка файла: {json_file}")
                process_single_file(json_file, csv_file, content_meta=None)
                self.add_progress(100)
                self.log(f"Готово. CSV файл: {csv_file}")
                self.enqueue("message_info", ("Успех", f"Обработка завершена.\nCSV файл: {csv_file}"))

            elif mode == "dir":
                json_dir = params["json_dir"]
                out_dir = params["out_dir"]

                self.log(f"Обработка директории: {json_dir}")
                count = process_directory(json_dir, out_dir, content_meta=None)
                self.add_progress(100)
                self.log(f"Готово. Создано CSV файлов: {count} в {out_dir}")
                self.enqueue(
                    "message_info",
                    ("Успех", f"Обработка завершена.\nСоздано CSV файлов: {count}\nКаталог: {out_dir}"),
                )

            else:
                prog_dir = params["prog_dir"]
                content_dir = params["content_dir"]
                reports_json_dir = params["reports_json_dir"]
                csv_out_dir = params["csv_out_dir"]

                self.log("=== Проверка контента ===")
                self.log(f"Программа: {prog_dir}")
                self.log(f"Контент: {content_dir}")
                self.log(f"Директория JSON отчётов: {reports_json_dir}")
                self.log(f"Директория CSV: {csv_out_dir}")

                total_steps = 5
                step = 100 / total_steps

                def on_step():
                    self.add_progress(step)

                success = run_linter_for_severities(
                    prog_dir,
                    content_dir,
                    reports_json_dir,
                    log_func=self.log,
                    progress_callback=on_step,
                )
                self.log(f"Успешных запусков linter: {success}")

                self.log("Чтение packages/package.spec...")
                content_meta = build_content_metadata_from_packages(content_dir)
                self.log(f"Найдено объектов контента в packages: {len(content_meta)}")

                self.log("Преобразование JSON отчётов в CSV (prefix_severity_date.csv)...")
                count = convert_reports_to_named_csvs(
                    content_dir,
                    reports_json_dir,
                    csv_out_dir,
                    content_meta=content_meta
                )
                self.add_progress(step)
                self.log(f"Готово. Создано CSV файлов: {count} в {csv_out_dir}")
                self.enqueue(
                    "message_info",
                    (
                        "Успех",
                        "Проверка контента завершена.\n"
                        f"Успешных запусков linter: {success}\n"
                        f"Создано CSV файлов: {count}\n"
                        f"Каталог CSV: {csv_out_dir}",
                    ),
                )

        except Exception as e:
            self.log(f"Ошибка: {e}")
            self.enqueue("message_error", ("Ошибка", f"Произошла ошибка:\n{e}"))
        finally:
            self.enqueue("running", False)


def main():
    root = tk.Tk()
    try:
        if getattr(sys, "frozen", False) and hasattr(sys, "executable"):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.abspath(os.path.dirname(__file__))
        icon_path = os.path.join(base_dir, "ContentValidator.ico")
        if os.path.exists(icon_path):
            root.iconbitmap(icon_path)
    except Exception:
        pass

    app = JsonToCsvApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
