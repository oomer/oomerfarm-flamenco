#! /usr/bin/env python3
"""
gui_bella.py — Bella .bsz → Flamenco simple-bella-render (cross-platform GUI)
==========================================================================

Tkinter/ttk front-end for the shared ``bella_submitter`` pipeline. Runs on any
Python 3 install with the stdlib ``tkinter`` module available: macOS, Linux,
Windows 11. No third-party packages required; HTTP/HTTPS (including mTLS) goes
through ``urllib``/``ssl`` exactly like :mod:`cli_bella`.

Platform notes
--------------
* **Windows:** the python.org installer ships a working Tk 8.6. Just run
  ``python gui_bella.py``.
* **Linux:** Tk is usually present; on minimal Debian/Ubuntu install the
  ``python3-tk`` package once (``sudo apt install python3-tk``). No ``pip``.
* **macOS:** Apple's Xcode-bundled ``/usr/bin/python3`` ships **Tk 8.5**, which
  aborts on modern macOS ("macOS 26 required, have 16"). Use the python.org
  installer or Homebrew (``brew install python-tk@3.13``) to get a working
  Tk 8.6. The GUI never launches here otherwise — the CLI (``--no-gui`` or
  :mod:`cli_bella`) keeps working because ``tkinter`` is only imported on
  GUI mode.

Run modes
---------
* No job-arg flags → GUI dialog.
* Any of ``--project / --comment / --bsz / --bella-version / --priority / --url``
  → batch mode (no dialog), same behaviour as :mod:`cli_bella`.
* ``--gui`` / ``--no-gui`` override the above.

Environment variables, defaults, and CLI flags are documented in
:mod:`bella_submitter` and :mod:`cli_bella`.
"""

from __future__ import annotations

import argparse
import os
import queue
import re
import sys
import threading
from typing import List, Optional

from bella_submitter import (
    APP_GUI,
    BELLA_VERSIONS,
    DEFAULT_BELLA_VERSION,
    PRIORITY_MAX,
    PRIORITY_MIN,
    SubmitState,
    create_arg_parser,
    default_manager_url_dropdown_index,
    manager_url_choices,
    resolve_submit_inputs,
    run_full_submission,
)


# ---------------------------------------------------------------------------
# stdout/stderr redirection → thread-safe queue → Text widget.
#
# ``run_full_submission`` prints progress with ``print(...)`` as it goes. To
# stream those lines into the GUI's log panel we replace sys.stdout/sys.stderr
# for the duration of the submission with a writer that enqueues each chunk
# onto a ``queue.Queue``. The main thread polls that queue via ``root.after``
# and appends to the ``Text`` widget, so all Tk calls stay on the main thread
# (Tk is not thread-safe).
# ---------------------------------------------------------------------------
class _QueueWriter:
    """File-like object that writes to an underlying stream *and* a Queue."""

    def __init__(self, primary, out_queue: "queue.Queue[str]") -> None:
        self._primary = primary
        self._queue = out_queue

    def write(self, s: str) -> int:
        try:
            self._primary.write(s)
        except Exception:
            pass
        if s:
            self._queue.put(s)
        return len(s)

    def flush(self) -> None:
        try:
            self._primary.flush()
        except Exception:
            pass


def _run_submission_threaded(
    state: SubmitState,
    out_queue: "queue.Queue[str]",
    done_queue: "queue.Queue[int]",
) -> None:
    """Runs in a worker thread; streams output into ``out_queue``, rc into ``done_queue``."""
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout = _QueueWriter(old_out, out_queue)
    sys.stderr = _QueueWriter(old_err, out_queue)
    try:
        rc = run_full_submission(APP_GUI, state)
    except Exception as exc:  # noqa: BLE001 — last-ditch so the GUI always gets rc
        out_queue.put(f"\nUnexpected error: {exc}\n")
        rc = 1
    finally:
        sys.stdout = old_out
        sys.stderr = old_err
    done_queue.put(rc)


# ---------------------------------------------------------------------------
# Error summarisation — mirrors rhino_bella._summarize_error so the post-submit
# message box highlights the most informative line (TLS, DNS, timeout, etc.)
# ---------------------------------------------------------------------------
_ERROR_NEEDLES = (
    "ERROR:",
    "TLS (mTLS)",
    "TLS:",
    "TLS handshake",
    "DNS:",
    "Network timeout",
    "Connection refused",
    "HTTP request failed",
    "Missing BSZ file",
    "Traceback (most recent call last):",
)


def _summarize_error(output: str) -> str:
    for line in reversed(output.splitlines()):
        s = line.strip()
        if not s:
            continue
        for needle in _ERROR_NEEDLES:
            if needle in s:
                return s
    for line in reversed(output.splitlines()):
        s = line.strip()
        if s:
            return s
    return "(no error text captured)"


def _extract(pattern: str, output: str) -> Optional[str]:
    m = re.search(pattern, output)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Tk dialog. Imports live inside ``_run_gui`` so batch mode still works on
# systems without Tk installed (e.g. a headless Linux box without python3-tk).
# ---------------------------------------------------------------------------
def _run_gui(s0: SubmitState) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, scrolledtext, ttk
    except ImportError as exc:
        print(
            "guiBella: tkinter not available in this Python install. "
            "On Debian/Ubuntu try: sudo apt install python3-tk. "
            f"Original error: {exc}",
            file=sys.stderr,
        )
        return 1

    url_choices = manager_url_choices()
    url_labels = [label for label, _v, _d in url_choices]
    url_values = [value for _l, value, _d in url_choices]
    url_details = [detail for _l, _v, detail in url_choices]

    bella_for_dialog = (
        s0.bella_version if s0.bella_version in BELLA_VERSIONS else DEFAULT_BELLA_VERSION
    )
    initial_url_index = default_manager_url_dropdown_index(s0)

    root = tk.Tk()
    root.title("guiBella — submit to Flamenco")
    root.minsize(680, 560)
    try:
        root.geometry("820x640")
    except Exception:
        pass

    # ttk theme: "clam" looks consistent across platforms and honours widget
    # colours better than the platform defaults on Linux. macOS/Windows users
    # see their native theme because we only switch if clam is available.
    style = ttk.Style(root)
    try:
        if "clam" in style.theme_names() and sys.platform.startswith("linux"):
            style.theme_use("clam")
    except Exception:
        pass

    # ----- Form frame -------------------------------------------------------
    form = ttk.Frame(root, padding=10)
    form.pack(fill="both", expand=False)
    # Two-column grid: label column fixed, control column stretches.
    form.columnconfigure(1, weight=1)

    # Project
    ttk.Label(form, text="Project").grid(row=0, column=0, sticky="e", padx=(0, 8), pady=4)
    project_var = tk.StringVar(value=s0.project_raw)
    project_entry = ttk.Entry(form, textvariable=project_var)
    project_entry.grid(row=0, column=1, sticky="ew", pady=4)

    # Manager URL
    ttk.Label(form, text="Manager URL").grid(row=1, column=0, sticky="e", padx=(0, 8), pady=4)
    url_var = tk.StringVar(value=url_labels[initial_url_index])
    url_combo = ttk.Combobox(
        form, textvariable=url_var, values=url_labels, state="readonly"
    )
    url_combo.grid(row=1, column=1, sticky="ew", pady=4)

    url_detail_var = tk.StringVar(value=url_details[initial_url_index])
    url_detail_lbl = ttk.Label(
        form, textvariable=url_detail_var, foreground="#666", wraplength=560, justify="left"
    )
    url_detail_lbl.grid(row=2, column=1, sticky="ew", pady=(0, 4))

    def _on_url_changed(_event=None) -> None:
        try:
            idx = url_labels.index(url_var.get())
        except ValueError:
            idx = 0
        url_detail_var.set(url_details[idx])

    url_combo.bind("<<ComboboxSelected>>", _on_url_changed)

    # Bella version
    ttk.Label(form, text="Bella version").grid(row=3, column=0, sticky="e", padx=(0, 8), pady=4)
    version_var = tk.StringVar(value=bella_for_dialog)
    version_combo = ttk.Combobox(
        form, textvariable=version_var, values=list(BELLA_VERSIONS), state="readonly"
    )
    version_combo.grid(row=3, column=1, sticky="ew", pady=4)

    # BSZ file (entry + browse button in a nested frame so the entry stretches)
    ttk.Label(form, text="BSZ file").grid(row=4, column=0, sticky="e", padx=(0, 8), pady=4)
    bsz_row = ttk.Frame(form)
    bsz_row.grid(row=4, column=1, sticky="ew", pady=4)
    bsz_row.columnconfigure(0, weight=1)
    bsz_var = tk.StringVar(
        value=s0.bsz_path if s0.bsz_path and os.path.isfile(s0.bsz_path) else ""
    )
    bsz_entry = ttk.Entry(bsz_row, textvariable=bsz_var)
    bsz_entry.grid(row=0, column=0, sticky="ew")

    def _on_browse() -> None:
        initial_dir = ""
        cur = bsz_var.get().strip()
        if cur and os.path.isfile(cur):
            initial_dir = os.path.dirname(cur)
        path = filedialog.askopenfilename(
            parent=root,
            title="Choose a Bella .bsz archive",
            initialdir=initial_dir or None,
            filetypes=[("Bella scene archive", "*.bsz"), ("All files", "*.*")],
        )
        if path:
            bsz_var.set(path)

    ttk.Button(bsz_row, text="Browse…", command=_on_browse).grid(
        row=0, column=1, padx=(6, 0)
    )

    # Priority
    priority_var = tk.IntVar(value=int(s0.priority))
    priority_label_var = tk.StringVar(value=f"Priority: {int(s0.priority)}")
    ttk.Label(form, textvariable=priority_label_var).grid(
        row=5, column=0, sticky="e", padx=(0, 8), pady=4
    )

    def _on_priority_changed(val: str) -> None:
        try:
            priority_label_var.set(f"Priority: {int(float(val))}")
        except (TypeError, ValueError):
            pass

    priority_scale = ttk.Scale(
        form,
        from_=PRIORITY_MIN,
        to=PRIORITY_MAX,
        orient="horizontal",
        variable=priority_var,
        command=_on_priority_changed,
    )
    priority_scale.grid(row=5, column=1, sticky="ew", pady=4)

    # Comment (multi-line Text)
    ttk.Label(form, text="Comment").grid(row=6, column=0, sticky="ne", padx=(0, 8), pady=4)
    comment_text = tk.Text(form, height=4, wrap="word")
    comment_text.grid(row=6, column=1, sticky="ew", pady=4)
    if s0.comment:
        comment_text.insert("1.0", s0.comment)

    # ----- Log pane ---------------------------------------------------------
    log_frame = ttk.LabelFrame(root, text="Output", padding=(8, 4))
    log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 6))
    log_box = scrolledtext.ScrolledText(
        log_frame, height=10, wrap="word", state="disabled"
    )
    log_box.pack(fill="both", expand=True)

    def _append_log(text: str) -> None:
        log_box.configure(state="normal")
        log_box.insert("end", text)
        log_box.see("end")
        log_box.configure(state="disabled")

    # ----- Button bar -------------------------------------------------------
    btn_bar = ttk.Frame(root, padding=(10, 0, 10, 10))
    btn_bar.pack(fill="x")
    submit_btn = ttk.Button(btn_bar, text="Submit")
    cancel_btn = ttk.Button(btn_bar, text="Cancel")
    close_btn = ttk.Button(btn_bar, text="Close", command=root.destroy)
    # Layout: spacer pushes Cancel + Submit to the right.
    btn_bar.columnconfigure(0, weight=1)
    ttk.Frame(btn_bar).grid(row=0, column=0, sticky="ew")
    cancel_btn.grid(row=0, column=1, padx=(0, 6))
    submit_btn.grid(row=0, column=2)
    # Close replaces Cancel after a finished submission so the user can read
    # the log before dismissing the window.
    close_btn.grid_forget()

    # ----- Submit flow ------------------------------------------------------
    # Exit code survives across Tk's mainloop via this list so main() can return
    # it once root.mainloop() unwinds.
    exit_code: List[int] = [0]
    out_queue: "queue.Queue[str]" = queue.Queue()
    done_queue: "queue.Queue[int]" = queue.Queue()
    captured_chunks: List[str] = []

    def _set_form_enabled(enabled: bool) -> None:
        widgets = [
            project_entry,
            url_combo,
            version_combo,
            bsz_entry,
            priority_scale,
            comment_text,
        ]
        for w in widgets:
            try:
                w.configure(state="normal" if enabled else "disabled")
            except tk.TclError:
                pass
        for child in bsz_row.winfo_children():
            if isinstance(child, ttk.Button):
                child.configure(state="normal" if enabled else "disabled")

    def _drain_queue_to_log() -> None:
        """Main-thread pump: move stdout chunks from worker thread into the Text widget."""
        drained_any = False
        try:
            while True:
                chunk = out_queue.get_nowait()
                captured_chunks.append(chunk)
                _append_log(chunk)
                drained_any = True
        except queue.Empty:
            pass

        try:
            rc = done_queue.get_nowait()
        except queue.Empty:
            root.after(80, _drain_queue_to_log)
            return

        # Worker finished — drain anything queued after the rc.
        try:
            while True:
                chunk = out_queue.get_nowait()
                captured_chunks.append(chunk)
                _append_log(chunk)
        except queue.Empty:
            pass

        exit_code[0] = int(rc)
        output = "".join(captured_chunks)

        # Swap the button row: hide Cancel/Submit, show Close.
        submit_btn.grid_forget()
        cancel_btn.grid_forget()
        close_btn.grid(row=0, column=2)
        _set_form_enabled(True)

        title = "guiBella — submission"
        if rc == 0:
            jid = _extract(r"Submitted Flamenco Bella job id=(\S+)", output) or "?"
            cpath = _extract(r"Checkout path:\s*(\S+)", output) or "?"
            mgr = ""
            for line in output.splitlines():
                if line.startswith("Manager:"):
                    mgr = line.split(":", 1)[1].strip()
                    break
            messagebox.showinfo(
                title,
                f"Submitted to Flamenco.\n\nJob id:   {jid}\nCheckout: {cpath}\nManager:  {mgr or '?'}",
                parent=root,
            )
        else:
            messagebox.showerror(
                title,
                "Submission FAILED.\n\n" + _summarize_error(output),
                parent=root,
            )

    def _on_submit() -> None:
        bsz_path = bsz_var.get().strip()
        project = project_var.get().strip()
        if not bsz_path:
            messagebox.showwarning("Missing file", "Please choose a .bsz file.", parent=root)
            return
        if not bsz_path.lower().endswith(".bsz"):
            messagebox.showwarning(
                "Wrong file type",
                f"File must end with .bsz.\n\nGot: {os.path.basename(bsz_path)}",
                parent=root,
            )
            return
        if not os.path.isfile(bsz_path):
            messagebox.showwarning("Missing file", f"File not found:\n{bsz_path}", parent=root)
            return
        if not project:
            messagebox.showwarning("Missing project", "Project cannot be empty.", parent=root)
            return

        try:
            idx = url_labels.index(url_var.get())
        except ValueError:
            idx = 0

        state = SubmitState(
            project_raw=project,
            bsz_path=bsz_path,
            bella_version=str(version_var.get()),
            priority=int(priority_var.get()),
            comment=comment_text.get("1.0", "end").rstrip("\n"),
            manager_url=url_values[idx],
            frames_spec="",
        )

        # Clear the log pane; worker writes every print() into it.
        log_box.configure(state="normal")
        log_box.delete("1.0", "end")
        log_box.configure(state="disabled")
        captured_chunks.clear()

        _set_form_enabled(False)
        submit_btn.configure(state="disabled")

        worker = threading.Thread(
            target=_run_submission_threaded,
            args=(state, out_queue, done_queue),
            name="guiBella-submit",
            daemon=True,
        )
        worker.start()
        root.after(80, _drain_queue_to_log)

    def _on_cancel() -> None:
        # Cancel is only live before submission starts — once the worker is
        # running we hide Cancel and show Close instead, so no mid-flight
        # cancellation to handle here.
        exit_code[0] = 0
        root.destroy()

    submit_btn.configure(command=_on_submit)
    cancel_btn.configure(command=_on_cancel)
    root.protocol("WM_DELETE_WINDOW", _on_cancel)
    project_entry.focus_set()

    root.mainloop()
    return exit_code[0]


# ---------------------------------------------------------------------------
# Decide between GUI and batch — same rule as rhino_bella: any explicit
# job flag forces batch so scripts/schedulers aren't blocked by a dialog.
# ---------------------------------------------------------------------------
def _decide_gui(args: argparse.Namespace) -> bool:
    if args.gui is True:
        return True
    if args.gui is False:
        return False
    any_job_arg = any(
        v is not None
        for v in (
            args.project,
            args.comment,
            args.bsz,
            args.bella_version,
            args.priority,
            getattr(args, "manager_url", None),
            getattr(args, "frames", None),
        )
    )
    return not any_job_arg


def main(argv: Optional[List[str]] = None) -> int:
    parser = create_arg_parser(
        prog="guiBella",
        description="Submit a Bella .bsz to Flamenco (tk GUI; single frame or multi-.bsz sequence on CLI).",
        include_gui=True,
    )
    args = parser.parse_args(argv)

    s0 = resolve_submit_inputs(args)

    if _decide_gui(args):
        return _run_gui(s0)
    return run_full_submission(APP_GUI, s0)


if __name__ == "__main__":
    _rc = main()
    if _rc:
        raise SystemExit(_rc)
