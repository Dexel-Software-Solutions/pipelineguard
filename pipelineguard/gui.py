"""Tkinter desktop UI for PipelineGuard."""
from __future__ import annotations

import queue
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

from . import SUPPORT, __version__
from .fixer import FAILED, fix_paths
from .report import to_html, to_json, to_markdown, to_sarif
from .rules import RULE_TITLES, SEVERITY_ORDER
from .scanner import ScanResult, scan_project

THEMES = {
    "light": {"bg": "#f0f0f0", "fg": "#1f2328", "field": "#ffffff", "sel": "#cfe3ff",
              "critical": "#f8b4b4", "high": "#fcd5b0", "medium": "#fdf0b0", "low": "#d7ecd0"},
    "dark": {"bg": "#1e1f22", "fg": "#e6e6e6", "field": "#2b2d30", "sel": "#3d5a80",
             "critical": "#6e2b2b", "high": "#7a4a1d", "medium": "#6b5f1f", "low": "#2f5a2f"},
}
GRADE_COLOR = {"A": "#2ea44f", "B": "#6fa300", "C": "#b08900", "D": "#d9680f", "F": "#d1242f"}
SEVERITIES = ("critical", "high", "medium", "low")


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"PipelineGuard {__version__} - CI/CD Security Auditor")
        self.geometry("1150x700")
        self.result: ScanResult | None = None
        self.view: list = []
        self.jobs: queue.Queue = queue.Queue()
        self.path = tk.StringVar()
        self.sev = tk.StringVar(value="all")
        self.query = tk.StringVar()
        self.dark = False
        self.sort_col: str | None = None
        self.sort_rev = False
        self._build()
        self._theme()
        self.query.trace_add("write", lambda *_: self._refresh())
        self.after(100, self._poll)

    # ---------- layout ----------
    def _build(self) -> None:
        menu = tk.Menu(self)
        m_file = tk.Menu(menu, tearoff=0)
        m_file.add_command(label="Open folder...", command=self._browse)
        m_file.add_command(label="Export report...", command=self._export)
        m_file.add_separator()
        m_file.add_command(label="Quit", command=self.destroy)
        m_view = tk.Menu(menu, tearoff=0)
        m_view.add_command(label="Toggle dark mode", command=self._toggle_theme)
        m_help = tk.Menu(menu, tearoff=0)
        m_help.add_command(label="Rules reference", command=self._rules_dialog)
        m_help.add_command(label="Support / Contact", command=self._support_dialog)
        m_help.add_command(label="About", command=self._about)
        for label, sub in (("File", m_file), ("View", m_view), ("Help", m_help)):
            menu.add_cascade(label=label, menu=sub)
        self.config(menu=menu)

        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Entry(top, textvariable=self.path).pack(side="left", fill="x", expand=True)
        ttk.Button(top, text="Browse", command=self._browse).pack(side="left", padx=4)
        self.scan_btn = ttk.Button(top, text="Scan", command=self._scan)
        self.scan_btn.pack(side="left")
        ttk.Button(top, text="Auto-fix...", command=self._autofix).pack(side="left", padx=4)
        ttk.Button(top, text="Export", command=self._export).pack(side="left")

        self.summary = ttk.Label(self, text="Choose a repository folder and press Scan.",
                                 font=("Segoe UI", 12, "bold"), padding=(8, 0))
        self.summary.pack(fill="x")

        bar = ttk.Frame(self, padding=(8, 6))
        bar.pack(fill="x")
        ttk.Label(bar, text="Severity:").pack(side="left")
        box = ttk.Combobox(bar, textvariable=self.sev, width=10, state="readonly",
                           values=("all", *SEVERITIES))
        box.pack(side="left", padx=4)
        box.bind("<<ComboboxSelected>>", lambda _e: self._refresh())
        ttk.Label(bar, text="Search:").pack(side="left", padx=(12, 0))
        ttk.Entry(bar, textvariable=self.query).pack(side="left", fill="x", expand=True, padx=4)

        cols = ("severity", "rule", "location", "title")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        for c, w in zip(cols, (90, 70, 330, 560), strict=True):
            self.tree.heading(c, text=c.capitalize(), command=lambda c=c: self._sort(c))
            self.tree.column(c, width=w, minwidth=w, anchor="w", stretch=(c == "title"))
        self.tree.pack(fill="both", expand=True, padx=8)
        self.tree.bind("<<TreeviewSelect>>", self._details)

        self.detail = tk.Text(self, height=7, wrap="word", state="disabled")
        self.detail.pack(fill="x", padx=8, pady=8)

        foot = ttk.Frame(self, padding=(8, 0, 8, 6))
        foot.pack(fill="x")
        self.status = ttk.Label(foot, text="Ready")
        self.status.pack(side="left")
        link = ttk.Label(foot, text=f"Support · {SUPPORT['name']}", foreground="#0969da",
                         cursor="hand2")
        link.pack(side="right")
        link.bind("<Button-1>", lambda _e: self._support_dialog())

    def _theme(self) -> None:
        t = THEMES["dark" if self.dark else "light"]
        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure(".", background=t["bg"], foreground=t["fg"])
        st.configure("Treeview", background=t["field"], fieldbackground=t["field"],
                     foreground=t["fg"], rowheight=24)
        st.map("Treeview", background=[("selected", t["sel"])],
               foreground=[("selected", t["fg"])])
        st.configure("TEntry", fieldbackground=t["field"], foreground=t["fg"])
        st.configure("TCombobox", fieldbackground=t["field"], foreground=t["fg"])
        self.configure(bg=t["bg"])
        self.detail.configure(bg=t["field"], fg=t["fg"], insertbackground=t["fg"])
        for sev in SEVERITIES:
            self.tree.tag_configure(sev, background=t[sev],
                                    foreground=t["fg"] if self.dark else "#111111")

    def _toggle_theme(self) -> None:
        self.dark = not self.dark
        self._theme()

    # ---------- background work ----------
    def _bg(self, fn, done) -> None:
        def work() -> None:
            try:
                res = fn()
            except Exception as exc:  # report every failure to the UI, never freeze it
                res = exc
            self.jobs.put((done, res))
        threading.Thread(target=work, daemon=True).start()

    def _poll(self) -> None:
        try:
            while True:
                done, res = self.jobs.get_nowait()
                done(res)
        except queue.Empty:
            pass
        self.after(100, self._poll)

    # ---------- actions ----------
    def _browse(self) -> None:
        d = filedialog.askdirectory()
        if d:
            self.path.set(d)

    def _scan(self) -> None:
        if not self.path.get():
            messagebox.showinfo("PipelineGuard", "Select a folder first.")
            return
        self.scan_btn.state(["disabled"])
        self.summary.config(text="Scanning...")
        root = self.path.get()          # read Tk variables on the main thread only
        self._bg(lambda: scan_project(root)[0], self._on_scan)

    def _on_scan(self, res) -> None:
        self.scan_btn.state(["!disabled"])
        if isinstance(res, Exception):
            messagebox.showerror("PipelineGuard", str(res))
            self.summary.config(text="Scan failed.")
            return
        self.result = res
        c = res.counts()
        self.summary.config(
            foreground=GRADE_COLOR[res.grade],
            text=f"Score {res.score}/100 (grade {res.grade})  |  critical {c['critical']}  "
                 f"high {c['high']}  medium {c['medium']}  low {c['low']}")
        warn = f" · {len(res.errors)} file(s) could not be analysed" if res.errors else ""
        self.status.config(text=f"{res.files_scanned} files · {res.workflows} workflows · "
                                f"{res.dockerfiles} Dockerfiles · {res.other_ci} other CI{warn}")
        self._refresh()

    def _refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.view = []
        if not self.result:
            return
        sev, q = self.sev.get(), self.query.get().lower()
        for f in self.result.findings:
            if sev != "all" and f.severity != sev:
                continue
            if q and q not in f"{f.rule_id} {f.file} {f.title} {f.snippet}".lower():
                continue
            self.view.append(f)
        keys = {"severity": lambda f: -SEVERITY_ORDER[f.severity], "rule": lambda f: f.rule_id,
                "location": lambda f: (f.file, f.line), "title": lambda f: f.title}
        if self.sort_col:
            self.view.sort(key=keys[self.sort_col], reverse=self.sort_rev)
        for i, f in enumerate(self.view):
            self.tree.insert("", "end", iid=str(i), tags=(f.severity,),
                             values=(f.severity, f.rule_id, f"{f.file}:{f.line}", f.title))

    def _sort(self, col: str) -> None:
        self.sort_rev = (not self.sort_rev) if self.sort_col == col else False
        self.sort_col = col
        self._refresh()

    def _details(self, _evt=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        f = self.view[int(sel[0])]
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", f"{f.rule_id} · {f.title}\n\nCode: {f.snippet}\n\nFix: {f.fix}")
        self.detail.config(state="disabled")

    def _export(self) -> None:
        if not self.result:
            messagebox.showinfo("PipelineGuard", "Run a scan first.")
            return
        fn = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[
            ("HTML", "*.html"), ("Markdown", "*.md"), ("JSON", "*.json"), ("SARIF", "*.sarif")])
        if not fn:
            return
        ext = fn.rsplit(".", 1)[-1].lower()
        render = {"json": to_json, "sarif": to_sarif, "md": to_markdown}.get(ext, to_html)
        with open(fn, "w", encoding="utf-8") as fh:
            fh.write(render(self.result))

    # ---------- auto-fix ----------
    def _autofix(self) -> None:
        root = self.path.get()
        if not root:
            messagebox.showinfo("PipelineGuard", "Select a folder first.")
            return
        win = tk.Toplevel(self)
        win.title("Auto-fix preview")
        win.geometry("900x560")
        pin = tk.BooleanVar(value=False)
        top = ttk.Frame(win, padding=8)
        top.pack(fill="x")
        ttk.Checkbutton(top, text="Also pin actions to commit SHAs (needs internet)",
                        variable=pin).pack(side="left")
        text = tk.Text(win, wrap="none", font=("Consolas", 10))
        text.pack(fill="both", expand=True, padx=8)
        info = ttk.Label(win, text="Click Preview to see the changes (nothing is written yet).")
        info.pack(fill="x", padx=8, pady=4)
        state = {"changes": []}
        notes: list[str] = []

        def preview() -> None:
            info.config(text="Computing...")
            use_pin = pin.get()
            FAILED.clear()
            notes.clear()
            self._bg(lambda: fix_paths(root, pin=use_pin, notes=notes), shown)

        def shown(res) -> None:
            if not win.winfo_exists():
                return
            text.delete("1.0", "end")
            if isinstance(res, Exception):
                info.config(text=f"Error: {res}")
                return
            state["changes"] = res
            text.insert("end", "\n".join(d for _, d in res) or "Nothing to fix.")
            if notes:
                text.insert("end", "\n\n# Skipped (needs manual review):\n"
                            + "\n".join(f"#  - {n}" for n in notes))
            note = (f" Could not pin {len(set(FAILED))} action(s): offline or rate-limited."
                    if FAILED else "")
            info.config(text=f"{len(res)} file(s) would change. Review, then Apply.{note}")

        def apply() -> None:
            if not state["changes"]:
                return
            if not messagebox.askyesno("Apply fixes", "Modify these workflow files now?\n"
                                       "(Tip: commit first so you can review the git diff.)"):
                return
            use_pin = pin.get()
            self._bg(lambda: fix_paths(root, pin=use_pin, write=True, notes=[]), applied)

        def applied(res) -> None:
            if win.winfo_exists():
                win.destroy()
            if isinstance(res, Exception):
                messagebox.showerror("PipelineGuard", str(res))
            else:
                self._scan()

        ttk.Button(top, text="Preview", command=preview).pack(side="right")
        ttk.Button(top, text="Apply", command=apply).pack(side="right", padx=6)

    # ---------- dialogs ----------
    def _link(self, parent, text: str, url: str) -> None:
        lab = ttk.Label(parent, text=text, foreground="#0969da", cursor="hand2")
        lab.pack(anchor="w", pady=2)
        lab.bind("<Button-1>", lambda _e: webbrowser.open(url))

    def _support_dialog(self) -> None:
        win = tk.Toplevel(self)
        win.title("Support")
        win.geometry("460x300")
        f = ttk.Frame(win, padding=18)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text=SUPPORT["name"], font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(f, text="Need help, found a bug or want a custom feature?\n"
                          "Reach out - we are happy to help.", justify="left").pack(
            anchor="w", pady=(4, 10))
        self._link(f, f"Email: {SUPPORT['email']}", f"mailto:{SUPPORT['email']}")
        self._link(f, f"GitHub: {SUPPORT['github']}", SUPPORT["github"])
        self._link(f, "Report an issue", SUPPORT["issues"])

        def copy() -> None:
            self.clipboard_clear()
            self.clipboard_append(SUPPORT["email"])
            copy_btn.config(text="Copied!")

        copy_btn = ttk.Button(f, text="Copy email address", command=copy)
        copy_btn.pack(anchor="w", pady=12)

    def _rules_dialog(self) -> None:
        win = tk.Toplevel(self)
        win.title("Rules reference")
        win.geometry("560x380")
        tv = ttk.Treeview(win, columns=("id", "title"), show="headings")
        tv.heading("id", text="Rule")
        tv.heading("title", text="Description")
        tv.column("id", width=80, stretch=False)
        for rid, title in RULE_TITLES.items():
            tv.insert("", "end", values=(rid, title))
        tv.pack(fill="both", expand=True, padx=8, pady=8)

    def _about(self) -> None:
        messagebox.showinfo("About PipelineGuard",
                            f"PipelineGuard {__version__}\nCI/CD pipeline security auditor\n\n"
                            f"by {SUPPORT['name']}\n{SUPPORT['email']}")


def main() -> None:
    App().mainloop()


if __name__ == "__main__":
    main()
