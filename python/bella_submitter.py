#! /usr/bin/env python3
"""
Shared Flamenco / Shaman submit path for Bella .bsz → simple-bella-render
(one frame) or bella-frames-render (sibling .bsz sequence, one task per frame).

HTTP/HTTPS (including mTLS) uses only the standard library: urllib and ssl.
No third-party packages are required.

Used by rhino_bella.py (Rhino + optional Eto UI) and cli_bella.py (plain CPython
on macOS, Linux, or Windows). This module has no DCC, Rhino, or .NET
dependencies.

Submission flow (orchestrated by _run_full_submission_impl)
------------------------------------------------------------------
1. _effective_manager_url      resolve state.manager_url to real http(s) base
                               (handles "auto" probe chain).
2. make_session                urllib session; ensure_public_ca_anchors (below)
                               + mTLS client cert for https://.
3. zipfile… extract          unpack to temp (one tree, or under `seq/…/` per .bsz).
4. **Single** .bsz → one scene, ``simple-bella-render``. **Sequence** (sibling
   ``.bsz``): discover + optional frame subset; extract **all** into **one** temp
   tree (shared ``res/``; each .bsx is root-level ``<stem>.bsx`` matching the .bsz
   name). All beauty
   frames land under ``…/renders/<checkout_path>/`` (flat names, like single-frame
   bella; good for ``ffmpeg``); post
   ``bella-frames-render`` (one task per frame).
5. collect_file_specs          walk the temp dir -> [(path, sha256, size)].
6. _pick_bella_scene           choose the .bsx scene to render
                               ($FLAMENCO_BELLA_SCENE can override; single .bsz).
7. upload_shaman_files         POST /shaman/checkout/requirements, then
                               POST /shaman/files/<sha>/<size> for each file
                               the manager still needs.
8. create_shaman_checkout      POST /shaman/checkout/create to link the uploaded
                               files into a worker-visible path.
9. submit_render_job / submit_bella_frames_job   POST /api/v3/jobs

Entry points: run_full_submission (prints progress, returns 0/1);
create_arg_parser and resolve_submit_inputs (shared CLI/env parsing).
"""

from __future__ import annotations

import argparse
import contextvars
import getpass
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime
from http.client import HTTPMessage
from typing import Any, Dict, List, NamedTuple, Optional, Tuple
from urllib.parse import urlparse

DEFAULT_FLAMENCO_BASE = "http://10.88.0.1:8080"
# Second hop for ``manager_url=auto`` / GUI “Auto (VPN, then public)”. Override with FLAMENCO_PUBLIC_URL.
_DEFAULT_PUBLIC_FALLBACK = "https://flamencosubmit.birdspit.com"
# ``SubmitState.manager_url`` when user picks auto-probe (not a real URL string).
MANAGER_URL_AUTO = "__flamenco_manager_auto__"
JOB_TYPE_NAME = "simple-bella-render"
JOB_TYPE_NAME_FRAMES = "bella-frames-render"

# Must match the `choices` list in simple-bella-render.js → JOB_TYPE.settings[bella_version].
BELLA_VERSIONS = ("25.3.0", "24.6.0")
DEFAULT_BELLA_VERSION = "25.3.0"
DEFAULT_PRIORITY = 50
PRIORITY_MIN = 1
PRIORITY_MAX = 100

# HTTP timeouts (seconds). Small JSON calls use a short limit so a wrong/dead
# manager (e.g. VPN off, bad IP) fails in tens of seconds, not 10+ minutes.
# Only bulk Shaman file uploads use a long window.
HTTP_TIMEOUT_API_S = 8.0
HTTP_TIMEOUT_UPLOAD_S = 600.0

_REL_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_REL_SEGMENT_LENIENT_REJECT = re.compile(r"[\x00-\x1f\x7f/\\]")

# Active submitter (cli vs rhino) for User-Agent and job naming.
_current_app: contextvars.ContextVar[Optional["AppProfile"]] = contextvars.ContextVar(
    "bella_submitter_app", default=None
)


@dataclass(frozen=True)
class AppProfile:
    """Submitter identity for metadata, job names, and HTTP User-Agent."""

    display_name: str
    banner_subtitle: str
    dcc: str
    user_agent: str
    default_job_name_prefix: str


APP_RHINO = AppProfile(
    display_name="rhinoBella",
    banner_subtitle="Rhino .bsz → Flamenco simple-bella-render job",
    dcc="rhino",
    user_agent="rhinoBella/1",
    default_job_name_prefix="rhinoBella",
)
APP_CLI = AppProfile(
    display_name="cliBella",
    banner_subtitle="Bella .bsz → Flamenco simple-bella-render (plain python3)",
    dcc="cli",
    user_agent="cliBella/1",
    default_job_name_prefix="cliBella",
)
APP_GUI = AppProfile(
    display_name="guiBella",
    banner_subtitle="Bella .bsz → Flamenco simple-bella-render (tk GUI)",
    dcc="gui",
    user_agent="guiBella/1",
    default_job_name_prefix="guiBella",
)


class SubmitState(NamedTuple):
    project_raw: str
    bsz_path: str
    bella_version: str
    priority: int
    comment: str
    # Non-empty: use as manager base. Empty: use FLAMENCO_MANAGER_URL / FLAMENCO_URL / default.
    manager_url: str
    # Multi-.bsz only: 1-based frame spec (e.g. "1,3,5-7") or "" for all. See parse_frame_index_spec.
    frames_spec: str


def _user_agent() -> str:
    a = _current_app.get()
    if a is None:
        return "bellaSubmitter/0"
    return a.user_agent


def _validate_rel_path(value: str, label: str) -> None:
    if not value:
        raise ValueError(f"{label} is required")
    if len(value) > 255:
        raise ValueError(f"{label} too long (max 255)")
    if "\\" in value or "\0" in value:
        raise ValueError(f"{label} contains disallowed characters")
    if value.startswith("/"):
        raise ValueError(f"{label} must be a relative path (no leading /)")
    for seg in value.split("/"):
        if seg in ("", ".", ".."):
            raise ValueError(f"{label} contains empty, '.', or '..' segment: {value!r}")
        if not _REL_SEGMENT_RE.match(seg):
            raise ValueError(f"{label} segment has invalid characters: {seg!r}")


def _validate_rel_path_lenient(value: str, label: str) -> None:
    if not value:
        raise ValueError(f"{label} is required")
    if len(value) > 1024:
        raise ValueError(f"{label} too long (max 1024)")
    if value.startswith("/"):
        raise ValueError(f"{label} must be a relative path (no leading /)")
    for seg in value.split("/"):
        if seg in ("", ".", ".."):
            raise ValueError(f"{label} contains empty, '.', or '..' segment: {value!r}")
        if _REL_SEGMENT_LENIENT_REJECT.search(seg):
            bad = _REL_SEGMENT_LENIENT_REJECT.search(seg).group(0)
            raise ValueError(
                f"{label} segment contains disallowed character {bad!r}: {seg!r}"
            )
        if seg != seg.strip():
            raise ValueError(
                f"{label} segment has leading/trailing whitespace: {seg!r}"
            )


def _here() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def default_base_url() -> str:
    """The configured manager URL: $FLAMENCO_MANAGER_URL → $FLAMENCO_URL → built-in LAN default."""
    return os.environ.get(
        "FLAMENCO_MANAGER_URL",
        os.environ.get("FLAMENCO_URL", DEFAULT_FLAMENCO_BASE),
    ).rstrip("/")


def default_public_url() -> str:
    """Public HTTPS manager URL used as the second hop in auto mode. $FLAMENCO_PUBLIC_URL overrides."""
    return os.environ.get("FLAMENCO_PUBLIC_URL", _DEFAULT_PUBLIC_FALLBACK).rstrip(
        "/"
    ) or _DEFAULT_PUBLIC_FALLBACK.rstrip("/")


def manager_url_probe_chain() -> Tuple[str, ...]:
    """Order used by auto mode: try VPN (LAN) first, then public HTTPS."""
    return (DEFAULT_FLAMENCO_BASE.rstrip("/"), default_public_url())


def _tcp_reachable_for_url(url: str, *, timeout: float) -> bool:
    """True if a TCP connect to the URL host:port succeeds (probes reachability only)."""
    p = urlparse(url)
    host = p.hostname
    if not host:
        return False
    port = p.port
    if port is None:
        port = 443 if (p.scheme or "").lower() == "https" else 80
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def pick_manager_url_auto(*, timeout: float = 1.5) -> str:
    """First reachable URL in manager_url_probe_chain, else first in chain."""
    chain = manager_url_probe_chain()
    for u in chain:
        if _tcp_reachable_for_url(u, timeout=timeout):
            print(
                f"Manager (auto): {u} — first reachable in VPN → public order"
            )
            return u
    u0 = chain[0] if chain else DEFAULT_FLAMENCO_BASE
    print(
        f"Manager (auto): none of {chain!r} answered TCP; trying {u0!r} anyway "
        f"(use a fixed --url or fix network/TLS if this fails).",
        file=sys.stderr,
    )
    return u0


# ---------------------------------------------------------------------------
# Shared "Manager URL" dropdown data (used by rhino_bella.py's Eto dialog and
# gui_bella.py's tk dialog). Centralised here so both GUIs always offer the
# same four choices and agree on what "env/default" means.
# ---------------------------------------------------------------------------
def manager_url_choices() -> List[Tuple[str, str, str]]:
    """Options for the Manager URL dropdown.

    Each entry is ``(short_label, value, detail)`` where:

    * ``short_label`` is the compact text shown in the dropdown itself.
    * ``value`` is what gets stored in ``SubmitState.manager_url``:
      the auto sentinel, a concrete URL, or ``""`` meaning "use env/default".
    * ``detail`` is a longer human-readable description of that choice
      (full URLs, what fallback happens, etc.) for a tooltip or status line.
    """
    lan = DEFAULT_FLAMENCO_BASE.rstrip("/")
    pub = default_public_url()
    return [
        (
            "Auto (VPN, then public)",
            MANAGER_URL_AUTO,
            f"Try LAN first ({lan}), fall back to public mTLS ({pub}).",
        ),
        ("VPN (LAN)", lan, f"Plain HTTP to the LAN manager at {lan}."),
        ("Public (mTLS)", pub, f"HTTPS with client cert to {pub}."),
        (
            "Environment / default",
            "",
            "Use $FLAMENCO_MANAGER_URL, $FLAMENCO_URL, or the built-in default.",
        ),
    ]


def default_manager_url_dropdown_index(state: SubmitState) -> int:
    """Pick the initial dropdown row for ``state.manager_url``.

    Index map (matches manager_url_choices):
    ``0=auto, 1=LAN, 2=public, 3=env/default``. Empty ``manager_url`` falls
    back to inspecting $FLAMENCO_* so the dropdown reflects what a batch run
    *would* resolve to without the user touching anything.
    """
    u = (state.manager_url or "").strip()
    lan = DEFAULT_FLAMENCO_BASE.rstrip("/")
    pub = default_public_url()
    if u == MANAGER_URL_AUTO or (u and u.lower() == "auto"):
        return 0
    if u == lan:
        return 1
    if u == pub:
        return 2
    if not u:
        env_url = default_base_url()
        if env_url == pub:
            return 2
        if env_url == lan:
            # Prefer Auto so a down VPN can still fall through to public mTLS.
            return 0
        return 3
    # Non-empty URL that doesn't match any known option: still show Auto so the
    # user clearly has to pick one before submitting.
    return 0


def _effective_manager_url(state: SubmitState) -> str:
    """Resolve manager base: ``auto`` → probe chain; else explicit; else env + default.

    Only ``http://`` and ``https://`` strings are returned as fixed bases; the auto
    sentinel and ``auto`` are never returned verbatim (avoids old/stale importers
    that treated any non-empty string as a URL).
    """
    u = (state.manager_url or "").strip()
    if not u:
        return default_base_url()
    if u == MANAGER_URL_AUTO or u.lower() == "auto":
        return pick_manager_url_auto()
    if u.startswith("http://") or u.startswith("https://"):
        return u.rstrip("/")
    # Corrupt value or pre-fix sentinel that leaked through: never pass to urllib.
    if "flamenco_manager_auto" in u or u.startswith("__"):
        return pick_manager_url_auto()
    raise ValueError(
        f"Manager URL must start with http:// or https://, or use 'auto'. Got: {u!r}"
    )


# Filenames treated as "not a client cert" during the auto-scan. ``ca.crt`` is
# the CA bundle written by ``./make-certs.sh`` — picking it up here would make
# the client try to authenticate as its own CA, which the Flamenco Manager
# will rightly reject. Add other pseudo-cert filenames here if they show up.
_MTLS_EXCLUDED_CERT_NAMES = frozenset({"ca.crt"})


def _mtls_search_dirs() -> List[str]:
    """Directories scanned for a client cert/key pair, in priority order.

    Beside-the-script is first because it's the simplest artist layout: ship
    the ``.py`` files plus ``<name>.crt`` + ``<name>.key`` in one folder, run.
    ``secrets/`` is second so the default output of ``./make-certs.sh`` (which
    writes into ``./secrets/``) keeps working for developers.
    """
    here = _here()
    return [here, os.path.join(here, "secrets")]


def _scan_dir_for_mtls_pair(dirname: str) -> Optional[Tuple[str, str]]:
    """First alphabetical ``*.crt`` with a matching ``*.key`` in ``dirname``.

    Returns ``(cert_path, key_path)`` or ``None``. ``ca.crt`` is skipped so
    artists who drop a folder of PEM files next to the scripts don't end up
    authenticating as the CA itself.
    """
    if not os.path.isdir(dirname):
        return None
    try:
        names = sorted(os.listdir(dirname))
    except OSError:
        return None
    for name in names:
        if not name.endswith(".crt") or name in _MTLS_EXCLUDED_CERT_NAMES:
            continue
        cert_path = os.path.join(dirname, name)
        key_path = os.path.join(dirname, name[:-4] + ".key")
        if os.path.isfile(cert_path) and os.path.isfile(key_path):
            return (cert_path, key_path)
    return None


def _default_mtls_paths() -> Tuple[str, str]:
    """Resolve the client cert/key pair to load.

    Lookup order:

    1. ``$FLAMENCO_MTLS_CERT`` / ``$FLAMENCO_MTLS_KEY`` — explicit override.
       If only one is set, the other is derived by swapping ``.crt`` <->
       ``.key`` so you can point at a single name and have the pair follow.
    2. First alphabetical ``<name>.crt`` + matching ``<name>.key`` next to
       the scripts (``ca.crt`` excluded).
    3. Same scan in ``{script_dir}/secrets/``.
    4. Fallback: ``{script_dir}/secrets/client.crt`` / ``client.key`` so the
       "file not found" error points at a stable, documented path.

    Filename is free-form on purpose — ``./make-certs.sh --name harvey`` writes
    ``harvey.crt`` + ``harvey.key``; dropping those next to the scripts just
    works without renaming.
    """
    cert_env = os.environ.get("FLAMENCO_MTLS_CERT", "").strip()
    key_env = os.environ.get("FLAMENCO_MTLS_KEY", "").strip()
    if cert_env or key_env:
        if cert_env and not key_env and cert_env.endswith(".crt"):
            key_env = cert_env[:-4] + ".key"
        elif key_env and not cert_env and key_env.endswith(".key"):
            cert_env = key_env[:-4] + ".crt"
        return (os.path.abspath(cert_env), os.path.abspath(key_env))

    for dirname in _mtls_search_dirs():
        pair = _scan_dir_for_mtls_pair(dirname)
        if pair is not None:
            return (os.path.abspath(pair[0]), os.path.abspath(pair[1]))

    here = _here()
    return (
        os.path.abspath(os.path.join(here, "secrets", "client.crt")),
        os.path.abspath(os.path.join(here, "secrets", "client.key")),
    )


def _mtls_not_found_message(missing: str) -> str:
    """User-facing text when we can't find a client cert/key in any search dir."""
    dirs = _mtls_search_dirs()
    return (
        f"HTTPS base URL requires a client {missing} but none was found.\n"
        "  Searched these directories for the first alphabetical\n"
        "  <name>.crt + matching <name>.key (ca.crt is skipped):\n"
        + "".join(f"    - {d}\n" for d in dirs)
        + "  Simplest fix: drop your <name>.crt and <name>.key\n"
        "  (from `./make-certs.sh --name <name>`) next to the submitter scripts.\n"
        "  Or set FLAMENCO_MTLS_CERT (FLAMENCO_MTLS_KEY is derived if omitted)."
    )


def _url_request_failure_message(url: str, e: Exception) -> str:
    """Turn urllib/socket failures into a short, user-actionable message."""
    host = (urlparse(url).hostname) or "?"
    text = f"{e}".lower()
    if (
        "nodename nor servname" in text
        or "name or service not known" in text
        or "getaddrinfo failed" in text
    ):
        return (
            f"DNS: cannot resolve {host!r} — the hostname is unknown on this network. "
            "Check spelling, VPN, and /etc/hosts. "
            f"Original error: {e}"
        )
    if "tlsv1_alert_unknown_ca" in text or "unknown ca" in text:
        return (
            f"TLS (mTLS): the server {host!r} did not accept your client certificate "
            "chain. Your CA (secrets/ca.crt) is not in the server's client_auth trust "
            "store, or you are using a client.crt signed by a different CA than the one "
            "the server trusts. Re-issue client.crt from the correct CA, or install "
            "secrets/ca.crt into the server's client_auth configuration and reload it. "
            f"Original error: {e}"
        )
    if "certificate verify failed" in text:
        paths = ssl.get_default_verify_paths()
        return (
            f"TLS: cannot verify the server cert for {host!r}. "
            "The submitter loads the OS public CA bundle when the default store is "
            "empty (see ensure_public_ca_anchors). If it still fails: server full chain in "
            "Caddy, or set SSL_CERT_FILE to a PEM with the needed public roots. "
            "For a private *server* CA, add that CA PEM. "
            f"Default verify paths: cafile={paths.cafile!r} capath={paths.capath!r}. "
            f"Original error: {e}"
        )
    if "handshake" in text or "ssl" in text:
        return (
            f"TLS handshake with {host!r} failed. "
            "Check the client cert/key pair, server hostname, and TLS version. "
            f"Original error: {e}"
        )
    if "timed out" in text or "timeout" in text:
        return (
            f"Network timeout talking to {host!r}. "
            "The host may be blocked, off-VPN, or overloaded. "
            f"Original error: {e}"
        )
    if "connection refused" in text:
        return (
            f"Connection refused by {host!r}. "
            "The Flamenco manager / Caddy may be down, or listening on a different "
            "port than the URL. "
            f"Original error: {e}"
        )
    return f"HTTP request failed: {e}"


def _manager_headers(*, content_type: Optional[str] = None) -> Dict[str, str]:
    h: Dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": _user_agent(),
    }
    if content_type:
        h["Content-Type"] = content_type
    return h


@dataclass
class _HttpResponse:
    """Response shape used by this module (status, body text, headers)."""

    status_code: int
    text: str
    headers: HTTPMessage


class ManagerSession:
    """HTTP(S) with optional client cert — stdlib only (``urllib`` + ``ssl``)."""

    __slots__ = ("_ssl",)

    def __init__(self, ssl_context: Optional[ssl.SSLContext]) -> None:
        self._ssl = ssl_context

    def get(
        self, url: str, *, headers: Dict[str, str], timeout: float
    ) -> _HttpResponse:
        return self._do("GET", url, None, headers, timeout)

    def post(
        self, url: str, *, data: bytes, headers: Dict[str, str], timeout: float
    ) -> _HttpResponse:
        return self._do("POST", url, data, headers, timeout)

    def _do(
        self,
        method: str,
        url: str,
        body: Optional[bytes],
        headers: Dict[str, str],
        timeout: float,
    ) -> _HttpResponse:
        req = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(
                req, context=self._ssl, timeout=timeout
            ) as r:
                raw = r.read()
                st = r.status
                hdrs = r.headers
        except urllib.error.HTTPError as e:
            st = e.code
            raw = e.read()
            hdrs = e.headers
        except (urllib.error.URLError, OSError) as e:
            raise RuntimeError(_url_request_failure_message(url, e)) from e
        text = raw.decode("utf-8", errors="replace")
        return _HttpResponse(st, text, hdrs)


# --- Server HTTPS: public CA anchors (e.g. Rhino’s empty default store) ---------
# Does not add secrets/ca.crt — that is for mTLS *client* trust on the server.

_PUBLIC_CA_CANDIDATES_DARWIN: Tuple[str, ...] = (
    "/private/etc/ssl/cert.pem",
    "/etc/ssl/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/opt/homebrew/etc/openssl/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
)
_PUBLIC_CA_CANDIDATES_LINUX: Tuple[str, ...] = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
)


def _iter_public_ca_candidate_paths() -> Tuple[str, ...]:
    if sys.platform == "darwin":
        return _PUBLIC_CA_CANDIDATES_DARWIN + _PUBLIC_CA_CANDIDATES_LINUX
    return _PUBLIC_CA_CANDIDATES_LINUX


def ensure_public_ca_anchors(
    ctx: ssl.SSLContext, *, out: Any = print, err: Any = print
) -> Optional[str]:
    """If ctx has no trust anchors, use SSL_CERT_FILE or the first OS bundle found."""
    env = (os.environ.get("SSL_CERT_FILE") or "").strip()
    if env and os.path.isfile(env):
        try:
            ctx.load_verify_locations(cafile=env)
            out(
                "Trust (server): verifying the site using your SSL_CERT_FILE "
                "setting (normal for custom or private CAs)."
            )
            return env
        except ssl.SSLError as e:
            err(
                f"Warning: could not load SSL_CERT_FILE ({os.path.basename(env)}): {e}",
                file=sys.stderr,
            )
    try:
        if ctx.get_ca_certs():
            return None
    except (ssl.SSLError, TypeError, AttributeError):
        pass
    for path in _iter_public_ca_candidate_paths():
        if not os.path.isfile(path):
            continue
        try:
            ctx.load_verify_locations(cafile=path)
            out(
                "Trust (server): HTTPS verification uses your system’s trusted "
                "Certificate Authorities (same idea as a web browser). "
                "This Python had none loaded by default."
            )
            return path
        except ssl.SSLError:
            continue
    return None


def _client_cert_expiry(cert_path: str) -> Optional[Tuple[int, str]]:
    """Return ``(days_remaining, not_after_iso)`` for a PEM client cert, or ``None``.

    Pre-flight check so a short-lived mTLS cert (default 30 days from
    make-certs.sh) surfaces *before* we start the Shaman upload rather than
    as a cryptic TLS error mid-submission. Uses ``ssl._ssl._test_decode_cert``,
    which is prefixed with an underscore but ships with every CPython build
    and is the only stdlib way to read ``notAfter`` without pulling in the
    ``cryptography`` package (and we want stdlib-only per project policy).
    """
    try:
        from ssl import _ssl  # type: ignore[attr-defined]
        parsed = _ssl._test_decode_cert(cert_path)  # type: ignore[attr-defined]
    except Exception:
        return None
    not_after = parsed.get("notAfter") if isinstance(parsed, dict) else None
    if not not_after:
        return None
    try:
        expires_epoch = ssl.cert_time_to_seconds(not_after)
    except ValueError:
        return None
    days_remaining = int(
        (expires_epoch - datetime.now().timestamp()) // 86400
    )
    try:
        expires_iso = datetime.utcfromtimestamp(expires_epoch).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
    except (OSError, OverflowError, ValueError):
        expires_iso = not_after
    return days_remaining, expires_iso


# Warn if the mTLS client cert expires in fewer than this many days. Default
# certs from make-certs.sh are 30 days, so 2 gives a clear "rotate now" window
# before outright failure. Set to 0 to silence the warning (expiry still
# aborts the run).
CLIENT_CERT_WARN_DAYS = 2


def make_session(base_url: str) -> ManagerSession:
    """Build a client for the URL scheme: ``https://`` uses mTLS from PEM paths."""
    scheme = (urlparse(base_url).scheme or "").lower()
    ssl_ctx: Optional[ssl.SSLContext] = None

    if scheme == "https":
        cert_path, key_path = _default_mtls_paths()
        if not os.path.isfile(cert_path):
            raise FileNotFoundError(_mtls_not_found_message("certificate"))
        if not os.path.isfile(key_path):
            raise FileNotFoundError(_mtls_not_found_message("private key"))
        # Same as testrhinotls.py: public OS anchors only (ensure_public_ca_anchors);
        # not secrets/ca.crt (that is the server's mTLS *client* trust, not
        # verifying the server's HTTPS cert).
        ssl_ctx = ssl.create_default_context()
        ensure_public_ca_anchors(ssl_ctx)
        ssl_ctx.load_cert_chain(cert_path, key_path)
        if ssl_ctx.post_handshake_auth is not None:
            ssl_ctx.post_handshake_auth = True

        # Pre-flight expiry check — cheaper to fail now with a clear message
        # than to let OpenSSL throw a CERTIFICATE_HAS_EXPIRED halfway through
        # a multi-file Shaman upload. Non-fatal if parsing fails for any
        # reason (old Python, unusual cert format) — we'd rather submit.
        expiry = _client_cert_expiry(cert_path)
        if expiry is None:
            print(f"Auth: mTLS (cert={cert_path}; expiry unknown)")
        else:
            days_left, expires_iso = expiry
            if days_left < 0:
                raise RuntimeError(
                    f"Client cert EXPIRED {abs(days_left)} day(s) ago "
                    f"(not_after {expires_iso}, path {cert_path}). "
                    f"Re-issue with: ./make-certs.sh --name <you>"
                )
            suffix = f"{days_left} day(s), expires {expires_iso}"
            if days_left < CLIENT_CERT_WARN_DAYS:
                print(
                    f"WARNING: client cert expires soon — {suffix}. "
                    f"Rotate with ./make-certs.sh before it lapses.",
                    file=sys.stderr,
                )
            print(f"Auth: mTLS (cert={cert_path}; expires in {suffix})")
    elif scheme == "http":
        if os.environ.get("FLAMENCO_MTLS_CERT") or os.environ.get("FLAMENCO_MTLS_KEY"):
            print(
                "WARNING: FLAMENCO_MTLS_CERT/KEY are set but URL is http://; "
                "ignoring cert (plain HTTP).",
                file=sys.stderr,
            )
        print("Auth: none (plain HTTP — expected on VPN)")
    else:
        raise ValueError(
            f"Unsupported URL scheme {scheme!r} in base URL {base_url!r}; "
            "expected http:// or https://."
        )
    return ManagerSession(ssl_ctx)


def _check_json_response(r: _HttpResponse, what: str) -> Any:
    ctype = (r.headers.get("Content-Type") or "").strip()
    text = (r.text or "").strip()
    if r.status_code >= 400:
        preview = text[:1200].replace("\n", " ")
        raise RuntimeError(f"{what}: HTTP {r.status_code} — {preview!r}")
    if not text:
        raise RuntimeError(
            f"{what}: empty body (HTTP {r.status_code}, "
            f"Content-Type={ctype!r}); expected JSON."
        )
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        preview = text[:1200].replace("\n", " ")
        raise RuntimeError(
            f"{what}: not JSON (Content-Type={ctype!r}): {e}; "
            f"body starts: {preview!r}"
        ) from e


def _submitter_platform() -> str:
    plat = sys.platform
    if plat.startswith("linux"):
        return "linux"
    if plat == "darwin":
        return "darwin"
    if plat == "win32":
        return "windows"
    return plat


def _slugify(value: str) -> str:
    s = (value or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = s.strip("_")
    return s or "unknown"


def _submitter_identity() -> Dict[str, str]:
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown"
    os_family = _submitter_platform()
    return {
        "user": user,
        "host": host,
        "os_family": os_family,
        "os": platform.platform(),
        "slug": f"{_slugify(user)}_{os_family}",
    }


def _iter_files(root: str):
    for dirpath, _, filenames in os.walk(root):
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def _sha256_and_size(path: str) -> Tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(64 * 1024)
            if not chunk:
                break
            n += len(chunk)
            h.update(chunk)
    return h.hexdigest(), n


def _pick_bella_scene(
    rows: List[Dict[str, Any]],
    bsz_path: str,
    explicit_override: str = "",
) -> str:
    all_paths = [r["path"] for r in rows]
    bsx_paths = [p for p in all_paths if p.lower().endswith(".bsx")]

    override = (explicit_override or "").strip()
    if override:
        if override not in all_paths:
            raise RuntimeError(
                f"FLAMENCO_BELLA_SCENE={override!r} is not in the BSZ. "
                f"Available .bsx entries: {bsx_paths or '(none)'}"
            )
        return override

    if not bsx_paths:
        raise RuntimeError(
            f"No .bsx scene found inside {os.path.basename(bsz_path)!r}. "
            "A Bella scene archive must contain at least one .bsx file."
        )

    if len(bsx_paths) == 1:
        return bsx_paths[0]

    bsz_basename = os.path.splitext(os.path.basename(bsz_path))[0].lower()
    matching = [
        p for p in bsx_paths
        if os.path.splitext(os.path.basename(p))[0].lower() == bsz_basename
    ]
    if matching:
        return matching[0]

    chosen = sorted(bsx_paths)[0]
    print(
        f"WARNING: {len(bsx_paths)} .bsx files in archive, none matching "
        f"{bsz_basename!r}; picking {chosen!r}. "
        f"Set FLAMENCO_BELLA_SCENE to override.",
        file=sys.stderr,
    )
    return chosen


def _bella_scene_path_for_merged_bsz(
    rows: List[Dict[str, Any]], bsz_path: str
) -> str:
    """Resolve the scene for *bsz_path* in the merged Shaman tree.

    **Contract:** for ``oom_bake_0.bsz`` there must be a root-level ``oom_bake_0.bsx`` in the
    upload (one path segment: ``<stem>.bsx`` at the checkout root). The ``.bsz`` and ``.bsx``
    stems must match (compared with ``casefold`` on the base name). If the file exists only
    under a subdir, or is missing, we raise a clear failure (assert-style).
    """
    bsz_stem = os.path.splitext(os.path.basename(bsz_path))[0]
    cfold = bsz_stem.casefold()
    at_root: List[str] = []
    nested_match: List[str] = []
    for r in rows:
        p = r["path"]
        if not p.lower().endswith(".bsx"):
            continue
        base = os.path.splitext(os.path.basename(p))[0]
        if base.casefold() != cfold:
            continue
        if "/" in p:
            nested_match.append(p)
        else:
            at_root.append(p)
    if len(at_root) == 1:
        return at_root[0]
    if len(at_root) > 1:
        raise RuntimeError(
            f"Assert failed: multiple root .bsx for stem {bsz_stem!r}: {at_root!r} "
            f"({os.path.basename(bsz_path)!r})"
        )
    if nested_match:
        raise RuntimeError(
            f"Assert failed: {bsz_stem}.bsx must be at the **root** of the archive (and merged "
            f"tree), not only under a directory. Off-root matches: {nested_match!r} "
            f"({os.path.basename(bsz_path)!r})"
        )
    have_root = [r["path"] for r in rows if "/" not in r["path"]]
    raise RuntimeError(
        f"Assert failed: root-level {bsz_stem}.bsx missing for {os.path.basename(bsz_path)!r}. "
        f"Top-level paths in manifest: {have_root[:40]!r}{'…' if len(have_root) > 40 else ''}"
    )


def discover_bsz_sequence(anchor: str) -> List[str]:
    """Return ordered list of .bsz paths in the same directory that share this sequence.

    A "sequence" is: same non-empty *prefix* of the file stem, with a decimal suffix
    (e.g. ``shot_0007.bsz`` → prefix ``shot_``). All ``<prefix><digits>.bsz`` in that
    directory are included, ordered by the numeric value of the suffix.

    If the anchor stem has no trailing digits, or no siblings match, returns
    ``[abs(anchor)]`` only.
    """
    ap = os.path.abspath(os.path.expanduser(anchor))
    d = os.path.dirname(ap)
    if not d or not os.path.isdir(d):
        return [ap]
    base = os.path.basename(ap)
    stem = os.path.splitext(base)[0]
    m = re.search(r"(\d+)$", stem)
    if not m:
        return [ap]
    num_ext = m.group(1)
    prefix = stem[: -len(num_ext)]
    if not prefix:
        return [ap]
    pat = re.compile(
        "^" + re.escape(prefix) + r"(\d+)" + re.escape(".bsz") + r"$", re.IGNORECASE
    )
    found: List[Tuple[str, int]] = []
    try:
        names = os.listdir(d)
    except OSError:
        return [ap]
    for name in names:
        mm = pat.match(name)
        if not mm:
            continue
        full = os.path.join(d, name)
        if os.path.isfile(full):
            found.append((full, int(mm.group(1))))
    if len(found) <= 1:
        return [ap]
    found.sort(key=lambda t: t[1])
    return [f for f, _ in found]


def parse_frame_index_spec(spec: str) -> List[int]:
    """Parse a 1-based frame index list for ``select_sequence_for_render`` (e.g. ``1,3,5-7``)."""
    acc = set()
    s = (spec or "").strip()
    if not s:
        return []
    for part in s.split(","):
        p = part.strip()
        if not p:
            continue
        if "-" in p:
            a, b = p.split("-", 1)
            lo, hi = int(a.strip()), int(b.strip())
            for i in range(min(lo, hi), max(lo, hi) + 1):
                acc.add(i)
        else:
            acc.add(int(p))
    return sorted(acc)


def select_sequence_for_render(
    discovered: List[str], spec: str
) -> List[str]:
    """Filter ``discovered`` (ordered .bsz paths) by 1-based indices in *spec*.

    *spec* empty → return a copy of *discovered*. Raises ``ValueError`` if nothing
    is selected in range.
    """
    if not discovered:
        return []
    s = (spec or "").strip()
    if not s:
        return list(discovered)
    n = len(discovered)
    wanted = parse_frame_index_spec(s)
    out = [discovered[i - 1] for i in wanted if 1 <= i <= n]
    if not out:
        raise ValueError(
            f"Frame spec {s!r} did not select any of 1–{n} in this sequence."
        )
    return out


def _unique_stem_slugs_for_bsz_list(paths: List[str]) -> List[str]:
    """One slug per .bsz for worker *output_tag* / *publish_stem*; disambiguate if stems collide after slugify."""
    seen: set = set()
    out: List[str] = []
    for p in paths:
        stem = os.path.splitext(os.path.basename(p))[0]
        base = _slugify(stem)
        slug = base
        n = 0
        while slug in seen:
            n += 1
            slug = f"{base}_{n}"
        seen.add(slug)
        out.append(slug)
    return out


def collect_file_specs(root: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for full in sorted(_iter_files(root)):
        rel = os.path.relpath(full, root)
        rel_posix = rel.replace(os.sep, "/")
        _validate_rel_path_lenient(rel_posix, f"manifest path {rel_posix!r}")
        sha, size = _sha256_and_size(full)
        rows.append({"path": rel_posix, "sha": sha, "size": size})
    return rows


def upload_shaman_files(
    session: ManagerSession,
    rows: List[Dict[str, Any]],
    root: str,
    base_url: str,
) -> None:
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise RuntimeError(f"Not a directory: {root!r}")
    if not rows:
        print("No files in extracted directory; nothing to upload.")
        return

    base = base_url.rstrip("/")
    manifest = [{"path": r["path"], "sha": r["sha"], "size": r["size"]} for r in rows]
    lookup = {r["path"]: os.path.join(root, *r["path"].split("/")) for r in rows}

    req_url = f"{base}/api/v3/shaman/checkout/requirements"
    try:
        r = session.post(
            req_url,
            data=json.dumps({"files": manifest}).encode("utf-8"),
            headers=_manager_headers(content_type="application/json"),
            timeout=HTTP_TIMEOUT_API_S,
        )
        data = _check_json_response(r, "POST /api/v3/shaman/checkout/requirements")
    except RuntimeError as e:
        raise RuntimeError(f"Shaman requirements request failed: {e}") from e

    pending = data.get("files") or []
    if not pending:
        print("All resources are already on Flamenco storage; nothing to upload.")
        return

    for spec in pending:
        path = spec["path"]
        sha = spec["sha"]
        size = int(spec["size"])
        local = lookup.get(path)
        if local is None or not os.path.isfile(local):
            raise RuntimeError(
                f"Shaman asked for unknown path {path!r} (not in local manifest)"
            )

        upload_url = f"{base}/api/v3/shaman/files/{sha}/{size}"
        with open(local, "rb") as f:
            payload = f.read()
        if len(payload) != size:
            raise RuntimeError(f"Size mismatch for {path}")

        try:
            up = session.post(
                upload_url,
                data=payload,
                headers={
                    **_manager_headers(content_type="application/octet-stream"),
                    "X-Shaman-Original-Filename": path,
                },
                timeout=HTTP_TIMEOUT_UPLOAD_S,
            )
        except RuntimeError as e:
            raise RuntimeError(f"Upload failed for {path}: {e}") from e
        if up.status_code == 208:
            print(f"Already stored: {path}")
        elif up.status_code >= 400:
            preview = (up.text or "")[:800]
            raise RuntimeError(
                f"Upload failed for {path}: HTTP {up.status_code} {preview}"
            )
        else:
            print(f"Uploaded {path}")

    print(f"Finished syncing {len(pending)} file(s) reported by the manager.")


def create_shaman_checkout(
    session: ManagerSession,
    manifest: List[Dict[str, Any]],
    checkout_path: str,
    base_url: str,
) -> None:
    base = base_url.rstrip("/")
    body = {
        "checkoutPath": checkout_path,
        "files": [{"path": r["path"], "sha": r["sha"], "size": r["size"]} for r in manifest],
    }
    try:
        r = session.post(
            f"{base}/api/v3/shaman/checkout/create",
            data=json.dumps(body).encode("utf-8"),
            headers=_manager_headers(content_type="application/json"),
            timeout=HTTP_TIMEOUT_API_S,
        )
    except RuntimeError as e:
        raise RuntimeError(f"Shaman checkout/create failed: {e}") from e
    if r.status_code >= 400:
        preview = (r.text or "")[:1200].replace("\n", " ")
        raise RuntimeError(
            f"POST /api/v3/shaman/checkout/create: HTTP {r.status_code} — {preview!r}"
        )
    print(f"Shaman checkout created: {checkout_path}")


def _resolve_job_type(
    session: ManagerSession, base: str, job_type_name: str
) -> Tuple[str, Optional[str]]:
    try:
        r = session.get(
            f"{base}/api/v3/jobs/types",
            headers=_manager_headers(),
            timeout=HTTP_TIMEOUT_API_S,
        )
        if r.status_code != 200:
            return (job_type_name, None)
        data = json.loads(r.text) if (r.text or "").strip() else {}
        for jt in data.get("job_types", []):
            if jt.get("label") == job_type_name or jt.get("name") == job_type_name:
                return (jt.get("name") or job_type_name, jt.get("etag"))
    except (RuntimeError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return (job_type_name, None)


def submit_render_job(
    session: ManagerSession,
    app: AppProfile,
    checkout_path: str,
    base_url: str,
    *,
    bella_scene: str,
    metadata: Optional[Dict[str, str]] = None,
    job_name: Optional[str] = None,
    priority: int = DEFAULT_PRIORITY,
    bella_version: Optional[str] = None,
) -> None:
    base = base_url.rstrip("/")
    job_type, etag = _resolve_job_type(session, base, JOB_TYPE_NAME)

    if bella_version is None:
        bella_version = (
            os.environ.get("FLAMENCO_BELLA_VERSION", "").strip()
            or DEFAULT_BELLA_VERSION
        )

    _validate_rel_path(checkout_path, "checkout_path")
    _validate_rel_path(bella_scene, "bella_scene")

    if bella_version not in BELLA_VERSIONS:
        raise ValueError(
            f"bella_version {bella_version!r} is not one of "
            f"{list(BELLA_VERSIONS)} — add it to bella_submitter.BELLA_VERSIONS and to "
            f"simple-bella-render.js and bella-frames-render.js "
            f"JOB_TYPE.settings.bella_version.choices to enable."
        )
    priority = max(PRIORITY_MIN, min(PRIORITY_MAX, int(priority)))

    settings = {
        "checkout_path": checkout_path,
        "bella_scene": bella_scene,
        "bella_version": bella_version,
    }

    payload: Dict[str, Any] = {
        "name": job_name or f"{app.default_job_name_prefix} {checkout_path}",
        "type": job_type,
        "priority": priority,
        "submitter_platform": _submitter_platform(),
        "settings": settings,
    }
    if metadata:
        payload["metadata"] = {k: str(v) for k, v in metadata.items() if v not in (None, "")}
    if etag:
        payload["type_etag"] = etag

    headers = _manager_headers(content_type="application/json")
    wid = os.environ.get("FLAMENCO_WORKER_ID", "")
    wsec = os.environ.get("FLAMENCO_WORKER_SECRET", "")
    if wid and wsec:
        headers["X-Flamenco-Worker-ID"] = wid
        headers["X-Flamenco-Worker-Secret"] = wsec

    try:
        r = session.post(
            f"{base}/api/v3/jobs",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            timeout=HTTP_TIMEOUT_API_S,
        )
        out = _check_json_response(r, "POST /api/v3/jobs")
        jid = out.get("id", "?")
        print(f"Submitted Flamenco Bella job id={jid}")
    except RuntimeError as e:
        raise RuntimeError(f"Job submit failed: {e}") from e


def submit_bella_frames_job(
    session: ManagerSession,
    app: AppProfile,
    checkout_path: str,
    base_url: str,
    *,
    frames: List[Dict[str, str]],
    metadata: Optional[Dict[str, str]] = None,
    job_name: Optional[str] = None,
    priority: int = DEFAULT_PRIORITY,
    bella_version: Optional[str] = None,
) -> None:
    """POST ``bella-frames-render`` with settings ``bella_frames_json`` (JSON of frame rows)."""
    base = base_url.rstrip("/")
    job_type, etag = _resolve_job_type(session, base, JOB_TYPE_NAME_FRAMES)

    if bella_version is None:
        bella_version = (
            os.environ.get("FLAMENCO_BELLA_VERSION", "").strip()
            or DEFAULT_BELLA_VERSION
        )

    _validate_rel_path(checkout_path, "checkout_path")
    normalized_frames: List[Dict[str, str]] = []
    for row in frames:
        _validate_rel_path(row["bella_scene"], "bella_scene")
        _validate_rel_path(row["output_tag"], "output_tag")
        ps = (row.get("publish_stem") or row.get("output_tag") or "").strip()
        if not ps:
            raise ValueError("each frame row needs publish_stem (or output_tag)")
        _validate_rel_path(ps, "publish_stem")
        rd = {k: str(v) for k, v in row.items() if v not in (None, "")}
        rd["publish_stem"] = ps
        normalized_frames.append(rd)
    if bella_version not in BELLA_VERSIONS:
        raise ValueError(
            f"bella_version {bella_version!r} is not one of {list(BELLA_VERSIONS)} — add it to "
            "bella_submitter.BELLA_VERSIONS and bella-frames-render.js (and simple-bella-render.js) "
            "bella_version.choices to enable."
        )
    priority = max(PRIORITY_MIN, min(PRIORITY_MAX, int(priority)))

    settings: Dict[str, Any] = {
        "checkout_path": checkout_path,
        "bella_version": bella_version,
        "bella_frames_json": json.dumps(normalized_frames),
    }

    payload: Dict[str, Any] = {
        "name": job_name
        or f"{app.default_job_name_prefix} {len(normalized_frames)} frames {checkout_path}",
        "type": job_type,
        "priority": priority,
        "submitter_platform": _submitter_platform(),
        "settings": settings,
    }
    if metadata:
        payload["metadata"] = {k: str(v) for k, v in metadata.items() if v not in (None, "")}
    if etag:
        payload["type_etag"] = etag

    headers = _manager_headers(content_type="application/json")
    wid = os.environ.get("FLAMENCO_WORKER_ID", "")
    wsec = os.environ.get("FLAMENCO_WORKER_SECRET", "")
    if wid and wsec:
        headers["X-Flamenco-Worker-ID"] = wid
        headers["X-Flamenco-Worker-Secret"] = wsec

    try:
        r = session.post(
            f"{base}/api/v3/jobs",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            timeout=HTTP_TIMEOUT_API_S,
        )
        out = _check_json_response(r, "POST /api/v3/jobs")
        jid = out.get("id", "?")
        print(
            f"Submitted Flamenco Bella sequence job id={jid} "
            f"({len(normalized_frames)} task(s))"
        )
    except RuntimeError as e:
        raise RuntimeError(f"Job submit failed: {e}") from e


def resolve_bsz_path(cli_override: Optional[str] = None) -> str:
    """--bsz > BELLA_BSZ > RHINO_BELLA_BSZ > SIMPLE_BELLA_BSZ > simple.bsz beside bella_submitter.py."""
    p = (cli_override or "").strip()
    if not p:
        p = (
            os.environ.get("BELLA_BSZ", "").strip()
            or os.environ.get("RHINO_BELLA_BSZ", "").strip()
            or os.environ.get("SIMPLE_BELLA_BSZ", "").strip()
        )
    if p:
        return os.path.abspath(os.path.expanduser(p))
    return os.path.join(_here(), "simple.bsz")


def create_arg_parser(
    *,
    prog: str,
    description: str,
    include_gui: bool,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description=description)
    parser.add_argument(
        "--project",
        default=None,
        help=(
            "Top-level namespace for the checkout path. "
            "Defaults to an auto-derived '{user}_{os_family}' slug. "
            "Falls back to $FLAMENCO_PROJECT if unset."
        ),
    )
    parser.add_argument(
        "--comment",
        default=None,
        help="Free-form note stamped into job metadata. Falls back to $FLAMENCO_COMMENT.",
    )
    parser.add_argument(
        "--bsz",
        default=None,
        help=(
            "Path to the .bsz archive. "
            "Overrides $BELLA_BSZ / $RHINO_BELLA_BSZ / $SIMPLE_BELLA_BSZ."
        ),
    )
    parser.add_argument(
        "--url",
        "--manager-url",
        dest="manager_url",
        default=None,
        metavar="URL",
        help=(
            "Flamenco manager base, or the word 'auto' to try the VPN (LAN) URL "
            "first, then the public https URL (see FLAMENCO_PUBLIC_URL). "
            "Overrides $FLAMENCO_MANAGER_URL and $FLAMENCO_URL when set to a real URL."
        ),
    )
    parser.add_argument(
        "--bella-version",
        dest="bella_version",
        default=None,
        choices=list(BELLA_VERSIONS),
        help=(
            f"Bella CLI version. Default {DEFAULT_BELLA_VERSION}. "
            "Falls back to $FLAMENCO_BELLA_VERSION if unset."
        ),
    )
    parser.add_argument(
        "--priority",
        type=int,
        default=None,
        metavar=f"[{PRIORITY_MIN}-{PRIORITY_MAX}]",
        help=f"Job priority, clamped to [{PRIORITY_MIN}, {PRIORITY_MAX}]. Default {DEFAULT_PRIORITY}.",
    )
    parser.add_argument(
        "--frames",
        default=None,
        metavar="SPEC",
        help=(
            "Multi-.bsz sequence only: 1-based frame indices, e.g. 1,3,5-7. "
            "Omit to render the full discovered sequence. "
            "Falls back to $FLAMENCO_FRAMES when not set on the CLI."
        ),
    )
    if include_gui:
        parser.add_argument(
            "--gui",
            dest="gui",
            action="store_true",
            default=None,
            help=(
                "Force the submission dialog (Eto in Rhino, tkinter in gui_bella). "
                "Fails if the GUI toolkit isn't available on this Python."
            ),
        )
        parser.add_argument(
            "--no-gui",
            dest="gui",
            action="store_false",
            help="Never show the dialog. Use CLI flags and environment variables only.",
        )
    return parser


def resolve_submit_inputs(args: argparse.Namespace) -> SubmitState:
    """Build submit fields from argv + environment + identity (no Eto)."""
    identity = _submitter_identity()
    project_default_raw = (
        args.project
        or os.environ.get("FLAMENCO_PROJECT", "").strip()
        or identity["slug"]
    )
    bsz_default = resolve_bsz_path(getattr(args, "bsz", None))
    bella_default = (
        getattr(args, "bella_version", None)
        or os.environ.get("FLAMENCO_BELLA_VERSION", "").strip()
        or DEFAULT_BELLA_VERSION
    )
    if bella_default not in BELLA_VERSIONS:
        bella_default = DEFAULT_BELLA_VERSION
    priority_default = (
        args.priority if getattr(args, "priority", None) is not None else DEFAULT_PRIORITY
    )
    comment_default = (
        (getattr(args, "comment", None) or os.environ.get("FLAMENCO_COMMENT", "")) or ""
    ).strip()
    url_raw = (getattr(args, "manager_url", None) or "").strip()
    if url_raw.lower() == "auto":
        url_override = MANAGER_URL_AUTO
    else:
        url_override = url_raw
    frames_from_cli = getattr(args, "frames", None)
    frames_default = (frames_from_cli or "").strip() or os.environ.get(
        "FLAMENCO_FRAMES", ""
    ).strip()
    return SubmitState(
        project_default_raw,
        bsz_default,
        bella_default,
        int(priority_default),
        comment_default,
        url_override,
        frames_default,
    )


def run_full_submission(app: AppProfile, state: SubmitState) -> int:
    """Shaman + job submit. Returns 0 on success, 1 on user/config/network error."""
    token = _current_app.set(app)
    try:
        return _run_full_submission_impl(app, state)
    finally:
        _current_app.reset(token)


def _print_submission_header_common(
    app: AppProfile, state: SubmitState, base: str, checkout_path: str
) -> None:
    identity = _submitter_identity()
    print(f"Checkout path: {checkout_path}")
    print(f"Submitter:     {identity['user']}@{identity['host']} ({identity['os_family']})")
    print(f"Bella version: {state.bella_version}")
    print(f"Priority:      {state.priority}")
    if state.comment:
        print(f"Comment:       {state.comment}")
    if (state.frames_spec or "").strip():
        print(f"Frame spec:    {state.frames_spec}")


def _print_submission_error(msg: str) -> None:
    print(f"\nERROR: submission stopped — {msg}")
    print(
        "  No Flamenco job was created. Fix the condition above "
        "(e.g. VPN, --url, mTLS cert/CA) and re-run."
    )
    print(f"ERROR: submission stopped — {msg}", file=sys.stderr)


def _submit_single_bella_zip(
    app: AppProfile,
    state: SubmitState,
    base: str,
    session: ManagerSession,
    bsz: str,
) -> int:
    """Single .bsz → ``simple-bella-render`` (one Shaman tree, one Flamenco task)."""
    identity = _submitter_identity()
    project = _slugify(state.project_raw)
    scene_base = _slugify(os.path.splitext(os.path.basename(bsz))[0]) or "scene"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    checkout_path = f"{project}/{scene_base}/{stamp}"

    metadata: Dict[str, str] = {
        "submitter_user": identity["user"],
        "submitter_host": identity["host"],
        "submitter_os": identity["os"],
        "submitter_dcc": app.dcc,
        "submitter_version": app.user_agent,
        "project": project,
        "scene_base": scene_base,
        "bsz_filename": os.path.basename(bsz),
    }
    if state.comment:
        metadata["comment"] = state.comment

    job_name = f"{project}/{scene_base} — {app.dcc} · bella {state.bella_version}"

    print(f"Job type:      simple-bella-render (1 frame)\n")
    _print_submission_header_common(app, state, base, checkout_path)
    print()

    out_dir = tempfile.mkdtemp(prefix="bella_bsz_")
    try:
        with zipfile.ZipFile(bsz, "r") as zf:
            for info in zf.infolist():
                if "\\" in info.filename:
                    info.filename = info.filename.replace("\\", "/")
                zf.extract(info, out_dir)

        rows = collect_file_specs(out_dir)
        if not rows:
            print("Extracted archive has no files.", file=sys.stderr)
            return 1

        try:
            bella_scene = _pick_bella_scene(
                rows, bsz, os.environ.get("FLAMENCO_BELLA_SCENE", "")
            )
        except RuntimeError as e:
            print(str(e), file=sys.stderr)
            return 1

        try:
            _validate_rel_path(bella_scene, "bella_scene")
        except ValueError as e:
            print(
                f"{e}\n"
                f"Rename the scene inside {os.path.basename(bsz)!r} so every path "
                "segment matches [A-Za-z0-9._-] (no spaces or other specials) and "
                "re-export.",
                file=sys.stderr,
            )
            return 1

        metadata["bella_scene"] = bella_scene
        print(f"Scene:         {bella_scene}")
        print()

        print(
            f"Shaman: {len(rows)} file(s) in manifest → "
            "requirements → upload → checkout → job …\n"
        )
        try:
            upload_shaman_files(session, rows, out_dir, base)
            create_shaman_checkout(session, rows, checkout_path, base)
            submit_render_job(
                session,
                app,
                checkout_path,
                base,
                bella_scene=bella_scene,
                metadata=metadata,
                job_name=job_name,
                priority=state.priority,
                bella_version=state.bella_version,
            )
        except RuntimeError as e:
            _print_submission_error(str(e))
            return 1
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
    return 0


def _submit_bella_sequence(
    app: AppProfile,
    state: SubmitState,
    base: str,
    session: ManagerSession,
    selected: List[str],
    *,
    discovered: List[str],
) -> int:
    """Several .bsz: extract **all** into one tree (shared ``res/``), one task per .bsx → ``bella-frames-render``."""
    identity = _submitter_identity()
    project = _slugify(state.project_raw)
    a0 = os.path.splitext(os.path.basename(selected[0]))[0]
    a1 = os.path.splitext(os.path.basename(selected[-1]))[0]
    scene_base = _slugify(f"{a0}_to_{a1}_n{len(selected)}")
    if len(scene_base) > 120:
        scene_base = _slugify(f"seq{len(selected)}_{a0}")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    checkout_path = f"{project}/{scene_base}/{stamp}"

    metadata: Dict[str, str] = {
        "submitter_user": identity["user"],
        "submitter_host": identity["host"],
        "submitter_os": identity["os"],
        "submitter_dcc": app.dcc,
        "submitter_version": app.user_agent,
        "project": project,
        "scene_base": scene_base,
        "bella_frame_count": str(len(selected)),
        "bella_sequence": "1",
        "bella_renders_layout": "flat_under_checkout",
        "bsz_first": os.path.basename(selected[0]),
        "bsz_last": os.path.basename(selected[-1]),
    }
    if state.comment:
        metadata["comment"] = state.comment

    job_name = (
        f"{project}/{scene_base} — {app.dcc} · bella {state.bella_version} "
        f"· {len(selected)} frames"
    )

    n_disc = len(discovered)
    if n_disc > len(selected) or (state.frames_spec or "").strip():
        print(
            f"Sequence:     {n_disc} matching .bsz in directory, "
            f"submitting {len(selected)} (see frame spec if subset)\n"
        )
    else:
        print(f"Sequence:     {len(selected)} .bsz file(s) in this job\n")

    print(
        f"Job type:      bella-frames-render ({len(selected)} Flamenco task(s), "
        f"1 per frame)\n"
    )
    _print_submission_header_common(app, state, base, checkout_path)
    print()

    out_dir = tempfile.mkdtemp(prefix="bella_bszseq_")
    try:
        # Unpack every .bsz into the same tree so res/ and shared assets merge; later archives
        # add or overwrite; each frame's .bsx should be named to match its .bsz (see
        # _bella_scene_path_for_merged_bsz).
        for bsz_p in selected:
            with zipfile.ZipFile(bsz_p, "r") as zf:
                for info in zf.infolist():
                    if "\\" in info.filename:
                        info.filename = info.filename.replace("\\", "/")
                    zf.extract(info, out_dir)

        rows = collect_file_specs(out_dir)
        if not rows:
            print("Sequence extract produced no files.", file=sys.stderr)
            return 1

        stem_slugs = _unique_stem_slugs_for_bsz_list(selected)
        frame_rows: List[Dict[str, str]] = []
        for bsz_p, slug in zip(selected, stem_slugs):
            try:
                bella_scene = _bella_scene_path_for_merged_bsz(rows, bsz_p)
            except RuntimeError as e:
                print(str(e), file=sys.stderr)
                return 1
            try:
                _validate_rel_path(bella_scene, "bella_scene")
            except ValueError as e:
                print(
                    f"{e}\n"
                    f"Invalid relative path for scene for {os.path.basename(bsz_p)!r}. "
                    "Use path segments in [A-Za-z0-9._-] only and re-export.",
                    file=sys.stderr,
                )
                return 1
            try:
                _validate_rel_path(slug, "output_tag")
            except ValueError as e:
                print(f"Invalid output tag for {bsz_p}: {e}", file=sys.stderr)
                return 1
            frame_rows.append(
                {
                    "bella_scene": bella_scene,
                    "output_tag": slug,
                    "publish_stem": slug,
                }
            )

        print(
            f"Shaman: {len(rows)} file(s) in one merged tree (shared res/; "
            f"{len(frame_rows)} .bsx by stem match) → requirements → "
            f"upload → checkout → {len(frame_rows)}-task job …\n"
            f"Render share: …/renders/<checkout_path>/<stem>.png (same rel path as single-frame bella)\n"
        )
        try:
            upload_shaman_files(session, rows, out_dir, base)
            create_shaman_checkout(session, rows, checkout_path, base)
            submit_bella_frames_job(
                session,
                app,
                checkout_path,
                base,
                frames=frame_rows,
                metadata=metadata,
                job_name=job_name,
                priority=state.priority,
                bella_version=state.bella_version,
            )
        except RuntimeError as e:
            _print_submission_error(str(e))
            return 1
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
    return 0


def _run_full_submission_impl(app: AppProfile, state: SubmitState) -> int:
    print(f"{app.display_name} — {app.banner_subtitle}\n")

    base = _effective_manager_url(state)
    print(f"Manager: {base}")

    try:
        session = make_session(base)
    except (FileNotFoundError, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 1
    print()

    if os.environ.get("FLAMENCO_PRINT_CONFIGURATION", "").strip() == "1":
        try:
            r = session.get(
                f"{base}/api/v3/configuration",
                headers=_manager_headers(),
                timeout=HTTP_TIMEOUT_API_S,
            )
            print("GET /api/v3/configuration →", r.status_code)
            if r.text:
                print(r.text[:2000])
        except RuntimeError as e:
            print(f"(configuration probe failed: {e})")

    bsz = state.bsz_path
    if not bsz or not os.path.isfile(bsz):
        print(
            f"Missing BSZ file: {bsz or '(none)'}\n"
            "Pass --bsz, set BELLA_BSZ (or RHINO_BELLA_BSZ / SIMPLE_BELLA_BSZ), "
            f"or place simple.bsz beside bella_submitter.py ({_here()}).",
            file=sys.stderr,
        )
        return 1

    discovered = discover_bsz_sequence(bsz)
    try:
        selected = select_sequence_for_render(discovered, state.frames_spec)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if len(selected) > 1:
        return _submit_bella_sequence(
            app, state, base, session, selected, discovered=discovered
        )
    return _submit_single_bella_zip(app, state, base, session, selected[0])
