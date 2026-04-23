# /opt/oomerfarm/lib/oom-sync.sh
#
# Transport primitives for the canonical Shaman store, with a worker-local
# content-addressed blob cache. Sourced by Flamenco job scripts.
#
# ---- Why a worker blob cache? -----------------------------------------------
# Shaman on the share is already a content-addressed store: checkouts are
# symlinks into $OOM_BLOB_STORE / mnt / oomerfarm / flamenco / file-store / stored
#
# Animations / Projects / Scenes / Users / Timestamping can all checkout
# an unlimited number of directories into the virtual file system with nearly 
# zero ballooning of disk space. Flamenco's network model requires workers have 
# shared access to these symlinks to make the virtual file system referenced 
# assets work relative to .blend files. 
#
# The natural progression of this system, is that each worker builds a local
# content-addressed store of blobs in $OOM_TMP_DISK/file-store/stored to take
# advantage of ssd/nvme speeds and avoid constantly hitting the Shaman server.
# As a task goes active, the manifestJson, provides a list of needed assets to
# render a scene so each worker checks if the blob store exists locally and if not 
# copies them from the Shaman store. A local checkout then creates a local virtual 
# filesystem and the renderer works off this. This addition makes multi-cloud, hybrid
# on-premise + cloud farms more feasible since internet speeds can ruin render times.
#
# LOCAL_CHECKOUT = $OOM_TMP_DISK/checkouts/$CHECKOUT_PATH   (hard links to blob cache)
# LOCAL_RENDER   = $OOM_TMP_DISK/renders/$CHECKOUT_PATH     (real files written by DCC)
#
# ---- Layout ------------------------------------------------------------------
# Shaman store:
#   Inputs — Shaman-owned, content-addressed symlinks:
#   $OOM_STORE_ROOT / $CHECKOUT_PATH / <path>           symlink
#   -> $OOM_BLOB_STORE / <sha[:2]> / <sha[2:]> / <size>.blob
#
# Worker mirror (same shard structure as Shaman store for inputs, so the prefix-strip
# in oom_fetch inherits whatever Shaman does on the share — no hardcoded layout
# here):
#   $OOM_TMP_DISK / file-store / stored / <sha[:2]> / <sha[2:]> / <size>.blob  
#   $OOM_TMP_DISK / checkouts  / $CHECKOUT_PATH / <path>  HARD LINK to local blob
#   $OOM_TMP_DISK / renders    / $CHECKOUT_PATH / <path>  real file (DCC writes here)
#
#   Outputs — worker-written, real files, kept OUT of the checkout tree so the
#   Shaman checkout stays a pure reflection of what the submitter uploaded:
#     $OOM_RENDER_ROOT / $CHECKOUT_PATH / <path>          real file
#
# Checkouts use HARD links, not symlinks, so that realpath(simple.bsx) returns
# .../checkouts/.../simple.bsx rather than .../files/.../<sha>.blob. Many DCCs
# (Bella, Blender, Houdini, …) resolve symlinks before running extension-based
# format detection — a symlink named simple.bsx pointing at 1946256.blob fails
# the format check. A hard link is indistinguishable from a regular file at the
# syscall level, so extension-based detection sees what the user named the file.
# Hard links also improve GC: evicting a cache entry can never break a running
# job because the checkout keeps the inode alive until it's cleaned up too.
#
# ---- Public API --------------------------------------------------------------
#   oom_fetch <checkout_path> <local_checkout>
#       Materialize the checkout as a symlink tree under <local_checkout>,
#       pulling any missing blobs from $OOM_BLOB_STORE into the worker cache.
#       Bumps mtime on cache-hit blobs so GC sees recent use.
#
#   oom_push  <local_src> <rel_dir>
#       Publish <local_src> (file or directory) to $OOM_RENDER_ROOT/<rel_dir>/.
#       Outputs are not content-addressed — plain rsync onto the share.
#       Intentionally disjoint from $OOM_STORE_ROOT so renders never pollute
#       a Shaman checkout.
#
# ---- Required worker env (flamenco-worker.service Environment=) --------------
#   OOM_STORE_ROOT   Shaman checkoutPath (matches shaman.checkoutPath in
#                    flamenco-manager.yaml; e.g. /mnt/oomerfarm/flamenco/jobs).
#   OOM_RENDER_ROOT  Where rendered outputs land on the share. Separate root
#                    from OOM_STORE_ROOT so checkouts stay input-only; typical
#                    sibling path e.g. /mnt/oomerfarm/flamenco/renders.
#   OOM_BLOB_STORE   The 'stored/' subdir of shaman.fileStorePath — i.e. the
#                    actual root the checkout symlinks resolve under. If
#                    fileStorePath is defaulted (common), it lives at
#                    <shaman-root>/file-store/stored. Verify on a worker:
#                      readlink -f "$OOM_STORE_ROOT"/<any-job>/*/<any-file> | head -1
#                    — everything before the first sha-shard (two hex chars)
#                    is the correct OOM_BLOB_STORE.
#   OOM_TMP_DISK     Fast local scratch (e.g. /tmp/oomerfarm on NVMe).
#
# ---- Required on PATH --------------------------------------------------------
#   rsync, find, readlink — all standard on RHEL-family workers.
#
# ---- GC ----------------------------------------------------------------------
# Cache eviction is out-of-band. See /opt/oomerfarm/bin/oom-gc (systemd timer).
#
# ---- Migration target (future) ----------------------------------------------
# This file is the POSIX/rsync implementation — it requires a mounted share and
# therefore a VPN (or LAN) path from the worker to the manager. The intended
# evolution is an HTTP-blob implementation that swaps rsync for content-addressed
# GETs against the manager (or an S3 / WebDAV backend), keeping the same
# oom_fetch/oom_push signatures and the same $OOM_TMP_DISK cache layout. When
# that version ships, only this file is replaced — job-type JS, submitters, and
# worker systemd env all stay identical. Track OOM_SYNC_IMPL (below) to tell
# which backend a given worker is running.
OOM_SYNC_IMPL="posix-rsync"
export OOM_SYNC_IMPL

: "${OOM_STORE_ROOT:?OOM_STORE_ROOT not set in worker env}"
: "${OOM_RENDER_ROOT:?OOM_RENDER_ROOT not set in worker env}"
: "${OOM_BLOB_STORE:?OOM_BLOB_STORE not set in worker env}"
: "${OOM_TMP_DISK:?OOM_TMP_DISK not set in worker env}"

# oom_fetch <checkout_path> <local_checkout>
#   Example: oom_fetch "$CHECKOUT_PATH" "$LOCAL_CHECKOUT"
#
# Enumerates every symlink + regular file under the checkout on the share.
# For share-side symlinks whose target lives in $OOM_BLOB_STORE, the script
# ensures the blob is present locally (pull-from-share-to-cache if missing,
# touch if already cached) and then creates a HARD LINK from the checkout's
# named path (e.g. simple.bsx) to the cache blob. Any non-symlink or
# off-store symlink is rsync'd as a real copy — a rare corner case
# (hand-placed files for testing, etc.) that silently falls back to the
# pre-cache behavior.
oom_fetch() {
    _of_rel="$1"
    _of_dst="$2"
    _of_src="$OOM_STORE_ROOT/$_of_rel"
    # Local blob cache mirrors the share's $OOM_BLOB_STORE (which is itself
    # Shaman's file-store/stored) — same shard layout, same filenames.
    _of_cache="$OOM_TMP_DISK/file-store/stored"

    if [ ! -d "$_of_src" ]; then
        echo "oom_fetch: no checkout at $_of_src" >&2
        return 1
    fi
    mkdir -p "$_of_dst"

    # The pipeline runs in a subshell; the caller's `set -euo pipefail`
    # propagates any failing rsync/ln/mkdir up to the task shell.
    find "$_of_src" \( -type l -o -type f \) -print | while IFS= read -r _f; do
        _rel_path="${_f#"$_of_src"/}"
        _local="$_of_dst/$_rel_path"
        mkdir -p "$(dirname "$_local")"

        if [ -L "$_f" ]; then
            _target=$(readlink -f "$_f")
            case "$_target" in
                "$OOM_BLOB_STORE"/*)
                    _blob_key="${_target#"$OOM_BLOB_STORE"/}"
                    _local_blob="$_of_cache/$_blob_key"
                    if [ ! -f "$_local_blob" ]; then
                        mkdir -p "$(dirname "$_local_blob")"
                        # Atomic cache write: rsync to .tmp then rename. Two
                        # workers racing on the same blob is safe — mv is
                        # atomic on the same filesystem, and both copies are
                        # byte-identical (content-addressed).
                        _tmp="$_local_blob.tmp.$$"
                        rsync -a "$_target" "$_tmp"
                        mv -f "$_tmp" "$_local_blob"
                    else
                        # Cache hit — bump mtime so LRU-style GC sees recent use.
                        touch "$_local_blob"
                    fi
                    # Hard link — NOT symlink. Symlinks would trip DCC format
                    # detectors that call realpath() before looking at the
                    # extension (they'd see <sha>.blob instead of simple.bsx).
                    # Hard links share the inode without that indirection.
                    ln -f "$_local_blob" "$_local"
                    ;;
                *)
                    # Share-side symlink that doesn't live under $OOM_BLOB_STORE
                    # — treat as a real file and copy it in (no cache, no hard
                    # link; rare, e.g. hand-placed scenes for testing).
                    rsync -aL "$_f" "$_local"
                    ;;
            esac
        else
            rsync -a "$_f" "$_local"
        fi
    done
}

# oom_push <local_src> <rel_dir>
#   Example: oom_push "$LOCAL_RENDER/" "$CHECKOUT_PATH"
#
# Publishes to $OOM_RENDER_ROOT, NOT $OOM_STORE_ROOT — outputs are always kept
# outside the Shaman checkout tree. A trailing slash on <local_src> means
# "contents of" (rsync convention); omit to copy the dir itself.
oom_push() {
    mkdir -p "$OOM_RENDER_ROOT/$2"
    rsync -a "$1" "$OOM_RENDER_ROOT/$2"/
}
