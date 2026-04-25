#! python3
"""
rhino_bella.py — Rhino → Bella .bsz → Flamenco simple-bella-render job
====================================================================

DCC-specific submitter for Rhino3D. Core HTTP/Shaman/zip logic lives in
bella_submitter.py (shared with cli_bella.py and gui_bella.py) so the pipeline
stays in sync across DCCs, the plain-Python CLI, and the cross-platform GUI.

Run modes
---------
* From Rhino's ScriptEditor with no args → Eto dialog (if Rhino/Eto load).
* From Rhino with any of --project/--comment/--bsz/--bella-version/--priority →
  batch mode, no dialog.
* From a plain shell → batch; --gui / --no-gui control dialog when in Rhino.

See bella_submitter and cli_bella for environment variables and full CLI flags.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, List, Optional

# Rhino's ScriptEditor keeps imported modules in sys.modules across runs, so a
# previously-loaded bella_submitter would mask edits to the file on disk. Drop
# any cached copy so the `import` below always reads fresh from disk. Safe no-op
# when running outside Rhino (sys.modules just didn't have the key).
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
sys.modules.pop("bella_submitter", None)
import bella_submitter
from bella_submitter import (
    APP_RHINO,
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


def _log_bella_submitter_identity() -> None:
    """Print which bella_submitter file/mtime Rhino actually loaded (cache canary)."""
    try:
        import datetime as _dt

        src = getattr(bella_submitter, "__file__", "<unknown>")
        mtime_s = "?"
        if src and os.path.isfile(src):
            mtime_s = _dt.datetime.fromtimestamp(os.path.getmtime(src)).isoformat(
                timespec="seconds"
            )
        print(f"Loaded bella_submitter: {src} (mtime={mtime_s})")
    except Exception:
        pass


_log_bella_submitter_identity()


class _Tee:
    """Duplicate writes to two streams (terminal/ScriptEditor + an in-memory buffer)."""

    def __init__(self, primary, buffer):
        self._primary = primary
        self._buffer = buffer

    def write(self, s):
        self._primary.write(s)
        self._buffer.write(s)
        return len(s)

    def flush(self):
        try:
            self._primary.flush()
        except Exception:
            pass


def _run_submission_with_capture(state: SubmitState):
    """Run the submission while ``tee``-ing stdout/stderr into a buffer for the dialog."""
    import io
    buf = io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout = _Tee(old_out, buf)
    sys.stderr = _Tee(old_err, buf)
    try:
        rc = run_full_submission(APP_RHINO, state)
    except Exception as e:  # noqa: BLE001 — last-ditch safety for the dialog path
        buf.write(f"\nUnexpected error: {e}\n")
        rc = 1
    finally:
        sys.stdout = old_out
        sys.stderr = old_err
    return rc, buf.getvalue()


def _extract_job_id(output: str) -> Optional[str]:
    import re as _re
    m = _re.search(r"Submitted Flamenco Bella job id=(\S+)", output)
    return m.group(1) if m else None


def _extract_checkout_path(output: str) -> Optional[str]:
    import re as _re
    m = _re.search(r"Checkout path:\s*(\S+)", output)
    return m.group(1) if m else None


def _extract_manager_line(output: str) -> Optional[str]:
    for line in output.splitlines():
        if line.startswith("Manager:"):
            return line.split(":", 1)[1].strip()
    return None


def _show_submission_result_dialog(rc: int, output: str) -> None:
    """Post-submit Eto MessageBox with a plain-language summary + output preview."""
    if not _eto_available():
        return
    try:
        import Eto.Forms as _ef
        from Eto.Forms import MessageBox
    except Exception:
        return

    title = "rhinoBella — submission"
    if rc == 0:
        jid = _extract_job_id(output) or "?"
        cpath = _extract_checkout_path(output) or "?"
        mgr = _extract_manager_line(output) or "?"
        headline = (
            "Submitted to Flamenco.\n\n"
            f"Job id:   {jid}\n"
            f"Checkout: {cpath}\n"
            f"Manager:  {mgr}\n"
        )
        msg_type = getattr(_ef.MessageBoxType, "Information", None)
    else:
        headline = "Submission FAILED.\n\n" + _summarize_error(output)
        msg_type = getattr(_ef.MessageBoxType, "Error", None)

    preview = _tail(output, max_lines=20, max_chars=1500)
    body = headline + ("\n\n— Last output —\n" + preview if preview else "")
    try:
        if msg_type is not None:
            MessageBox.Show(body, title, msg_type)
        else:
            MessageBox.Show(body, title)
    except Exception:
        try:
            MessageBox.Show(body, title)
        except Exception:
            pass


def _summarize_error(output: str) -> str:
    """Pull the most informative line out of captured output (e.g. TLS, DNS, timeout)."""
    needles = (
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
    for line in reversed(output.splitlines()):
        s = line.strip()
        if not s:
            continue
        for n in needles:
            if n in s:
                return s
    for line in reversed(output.splitlines()):
        s = line.strip()
        if s:
            return s
    return "(no error text captured)"


def _tail(output: str, *, max_lines: int, max_chars: int) -> str:
    lines = [ln for ln in output.splitlines() if ln.strip()]
    tail = "\n".join(lines[-max_lines:])
    if len(tail) > max_chars:
        tail = "…" + tail[-max_chars:]
    return tail


def _eto_available() -> bool:
    try:
        import Rhino  # noqa: F401
        import Eto.Forms  # noqa: F401
        import Eto.Drawing  # noqa: F401
    except Exception:
        return False
    return True


def _run_eto_dialog(
    *,
    project_default: str,
    bsz_default: str,
    bella_versions: tuple,
    bella_default: str,
    priority_default: int,
    comment_default: str,
    manager_url_dropdown_index: int,
) -> Optional[Dict[str, Any]]:
    import Rhino  # noqa: F401
    import Eto.Forms as _ef
    from Eto.Drawing import Padding, Size
    from Eto.Forms import (
        Button,
        Dialog,
        FileFilter,
        FilePicker,
        Label,
        MessageBox,
        Slider,
        DropDown,
        TableCell,
        TableLayout,
        TableRow,
        TextArea,
        TextBox,
    )

    FORM_LABEL_WIDTH = 110

    def _mk_label(text: str, fixed_width: bool = False):
        lbl = Label()
        lbl.Text = text
        if fixed_width:
            lbl.Width = FORM_LABEL_WIDTH
        return lbl

    def _mk_button(text: str, handler):
        btn = Button()
        btn.Text = text
        btn.Click += handler
        return btn

    url_choices = manager_url_choices()
    _url_values = [v for _lbl, v, _d in url_choices]
    _url_details = [d for _lbl, _v, d in url_choices]

    # Room for the longest tooltip-detail string + label width + padding; keeps
    # widgets readable on a 1280-wide display without requiring manual resize.
    DLG_DEFAULT = Size(820, 560)
    DLG_MIN = Size(680, 480)
    # Minimum width for every stretchy control — they'll grow beyond this as the
    # user resizes the dialog. We use MinimumSize (not Size) so xscale=True in
    # the form rows can actually stretch them; a fixed Size would pin width and
    # leave the extra dialog space as dead whitespace beside each control.
    CONTROL_MIN_WIDTH = 380

    def _min_width(ctrl, w: int) -> None:
        try:
            ctrl.MinimumSize = Size(w, 0)
        except Exception:
            pass

    class SubmitDialog(Dialog):
        def __init__(self):
            super().__init__()
            self.Title = "rhinoBella — submit to Flamenco"
            self.ClientSize = DLG_DEFAULT
            try:
                self.MinimumSize = DLG_MIN
            except Exception:
                pass
            self.Padding = Padding(10)
            self.Resizable = True
            self.result_values: Optional[Dict[str, Any]] = None
            self._url_values = _url_values
            self._url_details = _url_details

            self.project_box = TextBox()
            self.project_box.Text = project_default
            self.project_box.ToolTip = (
                "Top-level checkout namespace. Auto-filled with your user/OS slug "
                "(e.g. 'harvey_darwin'). Change to a real project name when the "
                "work deserves its own namespace on the share."
            )
            _min_width(self.project_box, CONTROL_MIN_WIDTH)

            self.version_drop = DropDown()
            for v in bella_versions:
                self.version_drop.Items.Add(v)
            try:
                self.version_drop.SelectedIndex = bella_versions.index(bella_default)
            except ValueError:
                self.version_drop.SelectedIndex = 0
            _min_width(self.version_drop, CONTROL_MIN_WIDTH)

            self.manager_url_drop = DropDown()
            for label, _val, _detail in url_choices:
                self.manager_url_drop.Items.Add(label)
            _mi = int(manager_url_dropdown_index)
            if _mi < 0 or _mi >= len(url_choices):
                _mi = 0
            self.manager_url_drop.SelectedIndex = _mi
            self.manager_url_drop.ToolTip = (
                "Auto tries the LAN host first, then the public mTLS host (TCP only). "
                "Pick a fixed host or 'Environment' to use FLAMENCO_* variables."
            )
            _min_width(self.manager_url_drop, CONTROL_MIN_WIDTH)
            # Detail label shows the full URL / explanation for the current pick
            # without needing to hover for a tooltip.
            self.manager_url_detail = Label()
            self.manager_url_detail.Text = self._detail_for(_mi)
            try:
                self.manager_url_detail.Wrap = _ef.WrapMode.Word
            except Exception:
                pass
            self.manager_url_drop.SelectedIndexChanged += self._on_manager_url_changed

            self.bsz_picker = FilePicker()
            bsz_filter = FileFilter()
            bsz_filter.Name = "Bella scene archive (*.bsz)"
            bsz_filter.Extensions = [".bsz"]
            self.bsz_picker.Filters.Add(bsz_filter)
            if bsz_default and os.path.isfile(bsz_default):
                self.bsz_picker.FilePath = bsz_default
            _min_width(self.bsz_picker, CONTROL_MIN_WIDTH)

            self.priority_slider = Slider()
            self.priority_slider.MinValue = PRIORITY_MIN
            self.priority_slider.MaxValue = PRIORITY_MAX
            self.priority_slider.Value = priority_default
            self.priority_slider.TickFrequency = 10
            self.priority_label = _mk_label(
                self._priority_label_text(priority_default), fixed_width=True
            )
            self.priority_slider.ValueChanged += self._on_priority_changed

            self.comment_box = TextArea()
            self.comment_box.AcceptsReturn = True
            self.comment_box.Text = comment_default or ""
            # Pin height only; width is free to stretch with the dialog.
            try:
                self.comment_box.Height = 80
            except Exception:
                pass
            _min_width(self.comment_box, CONTROL_MIN_WIDTH)
            try:
                self.comment_box.PlaceholderText = (
                    "Optional note — shows up in job metadata, not the job name."
                )
            except Exception:
                pass

            self.submit_btn = _mk_button("Submit", self._on_submit)
            self.DefaultButton = self.submit_btn

            self.cancel_btn = _mk_button("Cancel", self._on_cancel)
            self.AbortButton = self.cancel_btn

            # Two-column TableLayout: label column auto-sizes to its widest
            # label; control column carries ``(control, True)`` so its width
            # scales with the dialog. This is more predictable than DynamicLayout
            # for "make everything fill the dialog width."
            form = TableLayout()
            form.Padding = Padding(10)
            form.Spacing = Size(6, 6)

            # IronPython note: Eto's C# TableRow constructors rely on an implicit
            # Control -> TableCell conversion that doesn't fire through the .NET
            # bridge, so every cell is wrapped in ``TableCell(control, scale)``
            # explicitly. Second arg is ``scaleWidth`` — True means that column
            # stretches horizontally when the dialog resizes.
            def _cell(control, scale: bool = False) -> TableCell:
                return TableCell(control, scale)

            def _row(label_text: str, control) -> None:
                form.Rows.Add(
                    TableRow(_cell(_mk_label(label_text, fixed_width=True)), _cell(control, True))
                )

            _row("Project", self.project_box)
            _row("Manager URL", self.manager_url_drop)
            _row("", self.manager_url_detail)
            _row("Bella version", self.version_drop)
            _row("BSZ file", self.bsz_picker)
            # Priority: priority_label IS the left-column text ("Priority: 50");
            # it already has a fixed width so the rest of the rows stay aligned.
            form.Rows.Add(
                TableRow(_cell(self.priority_label), _cell(self.priority_slider, True))
            )
            _row("Comment", self.comment_box)

            # Flexible vertical spacer row — expands when the dialog is taller.
            spacer_row = TableRow()
            spacer_row.ScaleHeight = True
            form.Rows.Add(spacer_row)

            # Buttons pinned right: put them in a small inner TableLayout whose
            # first cell is a scaled spacer. Lives in the control column so the
            # label column stays empty on the button row.
            btn_bar = TableLayout()
            btn_bar.Spacing = Size(6, 0)
            btn_bar.Rows.Add(
                TableRow(_cell(None, True), _cell(self.cancel_btn), _cell(self.submit_btn))
            )
            form.Rows.Add(TableRow(_cell(None), _cell(btn_bar, True)))

            self.Content = form

        @staticmethod
        def _priority_label_text(val: int) -> str:
            return f"Priority: {int(val)}"

        def _on_priority_changed(self, sender, e):
            self.priority_label.Text = self._priority_label_text(self.priority_slider.Value)

        def _detail_for(self, idx: int) -> str:
            if 0 <= idx < len(self._url_details):
                return self._url_details[idx]
            return ""

        def _on_manager_url_changed(self, sender, e):
            self.manager_url_detail.Text = self._detail_for(
                int(self.manager_url_drop.SelectedIndex)
            )

        def _warn(self, message: str, title: str) -> None:
            try:
                MessageBox.Show(self, message, title, _ef.MessageBoxType.Warning)
            except (TypeError, AttributeError):
                MessageBox.Show(message, title)

        def _on_submit(self, sender, e):
            path = (self.bsz_picker.FilePath or "").strip()
            if not path:
                self._warn("Please choose a .bsz file.", "Missing file")
                return
            if not path.lower().endswith(".bsz"):
                self._warn(
                    f"File must end with .bsz.\n\nGot: {os.path.basename(path)}",
                    "Wrong file type",
                )
                return
            if not os.path.isfile(path):
                self._warn(f"File not found:\n{path}", "Missing file")
                return
            if not (self.project_box.Text or "").strip():
                self._warn("Project cannot be empty.", "Missing project")
                return

            idx = int(self.manager_url_drop.SelectedIndex)
            if idx < 0 or idx >= len(self._url_values):
                idx = 0
            self.result_values = {
                "project": (self.project_box.Text or "").strip(),
                "bella_version": str(self.version_drop.SelectedValue),
                "comment": (self.comment_box.Text or "").strip(),
                "priority": int(self.priority_slider.Value),
                "bsz": path,
                "manager_url": self._url_values[idx],
            }
            self.Close()

        def _on_cancel(self, sender, e):
            self.result_values = None
            self.Close()

    dlg = SubmitDialog()
    try:
        owner = Rhino.UI.RhinoEtoApp.MainWindow
    except Exception:
        owner = None
    if owner is not None:
        dlg.ShowModal(owner)
    else:
        dlg.ShowModal()
    return dlg.result_values


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
    return _eto_available() and not any_job_arg


def main(argv: Optional[List[str]] = None) -> int:
    p = create_arg_parser(
        prog="rhinoBella",
        description="Submit a Rhino Bella .bsz to Flamenco (single frame or multi-.bsz sequence).",
        include_gui=True,
    )
    args = p.parse_args(argv)

    s0 = resolve_submit_inputs(args)
    bella_for_dialog = s0.bella_version
    if bella_for_dialog not in BELLA_VERSIONS:
        bella_for_dialog = DEFAULT_BELLA_VERSION
    comment_for_dialog = s0.comment

    use_gui = _decide_gui(args)
    if use_gui:
        if not _eto_available():
            print(
                "--gui requested but Rhino/Eto imports failed. "
                "Run this script from Rhino's ScriptEditor, or drop --gui.",
                file=sys.stderr,
            )
            return 1
        gui_result = _run_eto_dialog(
            project_default=s0.project_raw,
            bsz_default=s0.bsz_path if os.path.isfile(s0.bsz_path) else "",
            bella_versions=BELLA_VERSIONS,
            bella_default=bella_for_dialog,
            priority_default=s0.priority,
            comment_default=comment_for_dialog,
            manager_url_dropdown_index=default_manager_url_dropdown_index(s0),
        )
        if gui_result is None:
            print("Cancelled.")
            return 0
        state = SubmitState(
            project_raw=gui_result["project"],
            bsz_path=gui_result["bsz"],
            bella_version=gui_result["bella_version"],
            priority=int(gui_result["priority"]),
            comment=gui_result["comment"],
            manager_url=gui_result.get("manager_url", s0.manager_url),
            frames_spec=s0.frames_spec,
        )
    else:
        state = s0

    # auto-URL resolution and sentinel handling happens inside bella_submitter's
    # _effective_manager_url (called by make_session); no local coercion needed.
    if use_gui:
        rc, captured = _run_submission_with_capture(state)
        _show_submission_result_dialog(rc, captured)
        return rc
    return run_full_submission(APP_RHINO, state)


if __name__ == "__main__":
    # Rhino's ScriptEditor flags any ``raise`` as the "exit point" of the script
    # (including ``raise SystemExit(0)`` on success). Only raise on non-zero so a
    # successful run falls through cleanly; the shell still sees the exit code.
    _rc = main()
    if _rc:
        raise SystemExit(_rc)
