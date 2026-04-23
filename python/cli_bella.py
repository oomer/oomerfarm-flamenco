#! /usr/bin/env python3
"""
cli_bella.py — Bella .bsz → Flamenco simple-bella-render (plain Python 3)
=======================================================================

Same submission path as rhino_bella (Shaman + job POST) with no DCC, Rhino, or
GUI dependencies. No third-party packages: HTTP/HTTPS (including mTLS) uses
the standard library only. Use from any system shell with Python 3: macOS,
Linux, and Windows 11 (``py -3`` or ``python`` is fine if that is Python 3).

Cross-platform notes
--------------------
* **Paths:** Use the platform path separator in ``--bsz``; ``os.path`` and
  ``~`` expansion are used internally. mTLS cert paths
  (``FLAMENCO_MTLS_CERT`` / ``KEY``) can be set to PEM files using normal
  Windows (``C:\\...``) or WSL-style paths, depending on your Python.
* **Manager URL:** ``--url https://…`` or ``--url auto`` (tries the LAN
  default, then the public host; override public with ``FLAMENCO_PUBLIC_URL``),
  or use ``FLAMENCO_MANAGER_URL`` / ``FLAMENCO_URL``. CLI wins over env.
* **HTTP vs HTTPS:** ``http://`` is plain; ``https://`` needs a client cert.
  Simplest drop-in: put a ``<name>.crt`` and matching ``<name>.key`` next to
  the .py scripts — the first alphabetical pair wins (``ca.crt`` is skipped).
  Also works: a ``secrets/`` subdir (what ``./make-certs.sh`` writes), or
  explicit paths via ``FLAMENCO_MTLS_CERT`` (``FLAMENCO_MTLS_KEY`` is derived
  from the cert's filename if unset).
* **BSZ / zip:** Windows-created .bsz archives with ``\\`` in zip entry names
  are normalized on extract (see bella_submitter).

Default manager URL, checkout layout, and env vars are documented in
bella_submitter.py; ``BELLA_BSZ`` is the DCC-agnostic default for a .bsz path
(also accepts ``RHINO_BELLA_BSZ`` / ``SIMPLE_BELLA_BSZ`` for compatibility).
"""

from __future__ import annotations

import sys
from typing import List, Optional

from bella_submitter import APP_CLI, create_arg_parser, resolve_submit_inputs, run_full_submission


def main(argv: Optional[List[str]] = None) -> int:
    p = create_arg_parser(
        prog="cliBella",
        description="Submit a Bella .bsz to Flamenco as a simple-bella-render job (plain python3).",
        include_gui=False,
    )
    args = p.parse_args(argv)
    state = resolve_submit_inputs(args)
    return run_full_submission(APP_CLI, state)


if __name__ == "__main__":
    # Only raise SystemExit when main() reports a failure so Rhino's
    # ScriptEditor doesn't red-highlight a clean run. The shell still
    # gets the exit code via SystemExit on non-zero.
    _rc = main()
    if _rc:
        raise SystemExit(_rc)
