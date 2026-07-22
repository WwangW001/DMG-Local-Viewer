from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from dmg_crypto import DmgError, decrypt_dmg, is_encrypted_dmg


APP_NAME = "DMG 本地查看器"


def resource_path(name: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / name


def run_hidden(args: list[str]) -> subprocess.CompletedProcess[str]:
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=flags,
        check=False,
    )


def parse_7z_slt(output: str, archive_path: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for raw_line in output.splitlines():
        line = raw_line.strip("\r")
        if not line.strip():
            if current:
                records.append(current)
                current = {}
            continue
        if " = " in line:
            key, value = line.split(" = ", 1)
            current[key.strip()] = value.strip()
    if current:
        records.append(current)

    archive_names = {str(archive_path), archive_path.name}
    return [
        record
        for record in records
        if record.get("Path")
        and record.get("Path") not in archive_names
        and record.get("Type") not in {"Dmg", "HFS", "APFS"}
    ]


class DmgViewer(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("920x620")
        self.minsize(760, 500)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.temp_context = tempfile.TemporaryDirectory(prefix="dmg_local_viewer_")
        self.temp_dir = Path(self.temp_context.name)
        self.archive_path: Path | None = None
        self.decrypted_path: Path | None = None
        self.last_extract_dir: Path | None = None
        self.source_stem = "DMG"
        self.busy = False

        self.dmg_var = tk.StringVar()
        self.status_var = tk.StringVar(value="请选择 DMG；加密文件会自动提示输入密码。")
        self.progress_var = tk.DoubleVar(value=0)

        self._build_ui()

    @property
    def seven_zip(self) -> Path:
        return resource_path("7z.exe")

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        header = ttk.Frame(self, padding=(18, 16, 18, 8))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        ttk.Label(header, text=APP_NAME, font=("Microsoft YaHei UI", 16, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 12)
        )
        ttk.Label(header, text="DMG 文件").grid(row=1, column=0, sticky="w", padx=(0, 10))
        self.dmg_entry = ttk.Entry(header, textvariable=self.dmg_var)
        self.dmg_entry.grid(row=1, column=1, sticky="ew")
        self.browse_button = ttk.Button(header, text="浏览…", command=self._browse_dmg)
        self.browse_button.grid(row=1, column=2, padx=(8, 0))

        self.open_button = ttk.Button(header, text="读取文件", command=self._open_dmg)
        self.open_button.grid(row=2, column=2, padx=(8, 0), pady=(10, 0))
        self.dmg_entry.bind("<Return>", lambda _event: self._open_dmg())

        note = ttk.Label(
            header,
            text="自动识别加密状态；仅加密 DMG 会提示密码。原始文件始终只读。",
            foreground="#555555",
        )
        note.grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 0))

        status = ttk.Frame(self, padding=(18, 4, 18, 8))
        status.grid(row=1, column=0, sticky="ew")
        status.columnconfigure(0, weight=1)
        ttk.Label(status, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(
            status, variable=self.progress_var, maximum=100, length=220
        )
        self.progress.grid(row=0, column=1, sticky="e", padx=(12, 0))

        content = ttk.Frame(self, padding=(18, 0, 18, 8))
        content.grid(row=2, column=0, sticky="nsew")
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            content,
            columns=("size", "modified"),
            show="tree headings",
            selectmode="extended",
        )
        self.tree.heading("#0", text="内部路径")
        self.tree.heading("size", text="大小")
        self.tree.heading("modified", text="修改时间")
        self.tree.column("#0", width=550, minwidth=280)
        self.tree.column("size", width=110, anchor="e")
        self.tree.column("modified", width=160)
        self.tree.grid(row=0, column=0, sticky="nsew")

        yscroll = ttk.Scrollbar(content, orient="vertical", command=self.tree.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll = ttk.Scrollbar(content, orient="horizontal", command=self.tree.xview)
        xscroll.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        actions = ttk.Frame(self, padding=(18, 6, 18, 16))
        actions.grid(row=3, column=0, sticky="ew")
        actions.columnconfigure(0, weight=1)
        self.extract_button = ttk.Button(
            actions, text="解压全部…", command=self._extract_all, state="disabled"
        )
        self.extract_button.grid(row=0, column=1, padx=(8, 0))
        self.folder_button = ttk.Button(
            actions, text="打开解压目录", command=self._open_extract_dir, state="disabled"
        )
        self.folder_button.grid(row=0, column=2, padx=(8, 0))

    def _browse_dmg(self) -> None:
        path = filedialog.askopenfilename(
            title="选择 DMG 文件",
            filetypes=[("Apple 磁盘映像", "*.dmg"), ("所有文件", "*.*")],
        )
        if path:
            self.dmg_var.set(path)
            self.open_button.focus_set()

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        normal = "disabled" if busy else "normal"
        self.dmg_entry.configure(state=normal)
        self.browse_button.configure(state=normal)
        self.open_button.configure(state=normal)
        if busy:
            self.extract_button.configure(state="disabled")
            self.folder_button.configure(state="disabled")
        elif self.archive_path:
            self.extract_button.configure(state="normal")
            self.folder_button.configure(state="normal" if self.last_extract_dir else "disabled")

    def _clear_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())

    def _remove_decrypted(self) -> None:
        if self.decrypted_path:
            try:
                self.decrypted_path.unlink(missing_ok=True)
            except OSError:
                pass
        self.archive_path = None
        self.decrypted_path = None

    def _open_dmg(self) -> None:
        if self.busy:
            return
        path = Path(self.dmg_var.get().strip().strip('"'))
        if not path.is_file():
            messagebox.showerror(APP_NAME, "请选择一个存在的 DMG 文件。")
            return
        if not self.seven_zip.is_file():
            messagebox.showerror(APP_NAME, "程序组件 7z.exe 缺失，请重新获取完整 EXE。")
            return

        encrypted = is_encrypted_dmg(path)
        password = ""
        if encrypted:
            password = simpledialog.askstring(
                APP_NAME,
                "检测到加密 DMG，请输入密码：",
                show="●",
                parent=self,
            )
            if not password:
                self.status_var.set("已取消密码输入。")
                return

        self.source_stem = path.stem
        self._remove_decrypted()
        self._clear_tree()
        self.progress_var.set(0)
        self.status_var.set("正在验证密码并解密…" if encrypted else "正在读取未加密 DMG…")
        self._set_busy(True)
        threading.Thread(
            target=self._open_worker,
            args=(path, password, encrypted),
            daemon=True,
        ).start()

    def _open_worker(self, path: Path, password: str, encrypted: bool) -> None:
        output_path = self.temp_dir / "decrypted.dmg"
        archive_path = path
        decrypted_path: Path | None = None

        def progress(done: int, total: int) -> None:
            percent = done * 100 / total
            self.after(0, self.progress_var.set, percent)
            self.after(0, self.status_var.set, f"正在解密… {percent:.0f}%")

        try:
            if encrypted:
                decrypt_dmg(path, password, output_path, progress)
                archive_path = output_path
                decrypted_path = output_path
            password = ""
            result = run_hidden(
                [str(self.seven_zip), "l", "-slt", "-sccUTF-8", "--", str(archive_path)]
            )
            if result.returncode != 0:
                raise DmgError(
                    "DMG 无法读取；镜像可能已损坏，或其中的文件系统暂不受支持。\n\n"
                    + (result.stderr.strip() or result.stdout.strip() or "7-Zip 无法读取镜像。")
                )
            records = parse_7z_slt(result.stdout, archive_path)
            self.after(0, self._open_succeeded, archive_path, decrypted_path, records)
        except Exception as exc:
            password = ""
            try:
                output_path.unlink(missing_ok=True)
            except OSError:
                pass
            self.after(0, self._operation_failed, str(exc))

    def _open_succeeded(
        self,
        archive_path: Path,
        decrypted_path: Path | None,
        records: list[dict[str, str]],
    ) -> None:
        self.archive_path = archive_path
        self.decrypted_path = decrypted_path
        for record in records:
            path = record.get("Path", "")
            folder = record.get("Folder") == "+"
            size = "" if folder else self._format_size(record.get("Size", ""))
            label = path + ("/" if folder and not path.endswith("/") else "")
            self.tree.insert(
                "", "end", text=label, values=(size, record.get("Modified", ""))
            )
        self.progress_var.set(100)
        self.status_var.set(f"读取完成：发现 {len(records)} 个条目。")
        self._set_busy(False)

    @staticmethod
    def _format_size(value: str) -> str:
        try:
            size = int(value)
        except (TypeError, ValueError):
            return value
        units = ("B", "KB", "MB", "GB", "TB")
        amount = float(size)
        unit = units[0]
        for unit in units:
            if amount < 1024 or unit == units[-1]:
                break
            amount /= 1024
        return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"

    def _extract_all(self) -> None:
        if self.busy or not self.archive_path:
            return
        parent = filedialog.askdirectory(title="选择保存位置")
        if not parent:
            return
        destination = self._new_extract_directory(Path(parent))
        destination.mkdir()
        self.status_var.set("正在解压全部文件…")
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        self._set_busy(True)
        threading.Thread(
            target=self._extract_worker, args=(destination,), daemon=True
        ).start()

    def _new_extract_directory(self, parent: Path) -> Path:
        invalid = '<>:"/\\|?*'
        safe_stem = "".join("_" if char in invalid else char for char in self.source_stem)
        safe_stem = safe_stem.strip(" .") or "DMG"
        candidate = parent / f"{safe_stem}_解压"
        suffix = 2
        while candidate.exists():
            candidate = parent / f"{safe_stem}_解压_{suffix}"
            suffix += 1
        return candidate

    def _extract_worker(self, destination: Path) -> None:
        assert self.archive_path is not None
        result = run_hidden(
            [
                str(self.seven_zip),
                "x",
                "-y",
                "-sccUTF-8",
                f"-o{destination}",
                "--",
                str(self.archive_path),
            ]
        )
        if result.returncode == 0:
            self.after(0, self._extract_succeeded, destination)
        else:
            details = result.stderr.strip() or result.stdout.strip() or "7-Zip 解压失败。"
            self.after(0, self._operation_failed, details)

    def _extract_succeeded(self, destination: Path) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress_var.set(100)
        self.last_extract_dir = destination
        self.status_var.set(f"解压完成：{destination}")
        self._set_busy(False)
        messagebox.showinfo(APP_NAME, f"文件已解压到：\n{destination}")

    def _operation_failed(self, details: str) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress_var.set(0)
        self.status_var.set("操作失败。")
        self._set_busy(False)
        messagebox.showerror(APP_NAME, details)

    def _open_extract_dir(self) -> None:
        if self.last_extract_dir and self.last_extract_dir.is_dir():
            os.startfile(self.last_extract_dir)

    def _on_close(self) -> None:
        try:
            self.temp_context.cleanup()
        finally:
            self.destroy()


if __name__ == "__main__":
    app = DmgViewer()
    app.mainloop()
