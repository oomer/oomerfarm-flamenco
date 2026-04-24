// Deploy next to flamenco-manager: /opt/oomerfarm/scripts/simple-bella-render.js
//
// Generic single-frame Bella render job type. "Simple" because it's one frame per job;
// a forthcoming advancedBellaRender.js will handle frame ranges / animation. DCC-agnostic —
// Houdini / Blender / Rhino / etc. all submit by producing a .bsz and posting here.
// Shaman is the underlying transport (deduplicating content-addressed upload + checkout
// symlinks on the shared store); it's the default transport and no longer called out
// in the job-type name.
//
// ---- Task structure ---------------------------------------------------------
// ONE Flamenco task ("Render single frame"), FOUR commands run serially on the
// same worker (Flamenco never splits a task's commands across workers — this is
// how we structurally guarantee that bella writes to a local disk that publish
// then reads from):
//
//   1. materialize  — fetch checkout tree from canonical store → LOCAL_CHECKOUT
//   2. bella        — bella_cli reads LOCAL_CHECKOUT, writes LOCAL_RENDER
//   3. publish      — rsync LOCAL_RENDER → $OOM_RENDER_ROOT/$CHECKOUT_PATH/
//   4. thumbnail    — ffmpeg preview.jpg from LOCAL_RENDER, push to render store
//                     (uses blender-render command type so Flamenco's "Saved:"
//                     regex surfaces the preview in the web UI)
//
// Inputs and outputs are kept in disjoint trees everywhere (on the share and
// on the worker) so the Shaman checkout stays a pure reflection of what the
// submitter uploaded, and publish is a single unconditional rsync.
//
// ---- Transport abstraction -------------------------------------------------
// Every command sources /opt/oomerfarm/lib/oom-sync.sh on the worker, which
// defines two shell functions and asserts OOM_STORE_ROOT / OOM_RENDER_ROOT /
// OOM_BLOB_STORE / OOM_TMP_DISK:
//
//     oom_fetch <checkout_path> <local_checkout>
//     oom_push  <local_src>     <rel_dir>
//
// These are the ONLY places that touch the canonical store. The current
// library mirrors Shaman's content-addressed layout onto worker NVMe:
// checkouts materialize as HARD-LINK trees into a local blob cache
// ($OOM_TMP_DISK/file-store/stored/…, mirroring the share's layout), so
// animation-style jobs that share textures / meshes across timestamped
// checkouts only pay the copy cost for new blobs.
// Hard links (not symlinks) so DCC format detectors that call realpath() see
// simple.bsx rather than <sha>.blob. Cache eviction is handled by
// /opt/oomerfarm/bin/oom-gc (systemd timer).
//
// This JS is transport-agnostic. When workers migrate to REST / WebDAV / S3
// / etc., the library's function bodies are the single point of change —
// the manager never has to be redeployed. See oom-sync.sh on each worker.
//
// REQUIRED on every worker:
//   - /opt/oomerfarm/lib/oom-sync.sh present and readable
//   - rsync installed (dnf install -y rsync)
// Command scripts fail fast if either is missing.
//
// ---- Submitter responsibility -----------------------------------------------
// The submitter (e.g. rhino_bella.py) owns Shaman: it uploads files via
// /api/v3/shaman/files/… and creates the named checkout via /api/v3/shaman/checkout/create
// BEFORE posting the job. By the time this script runs on a worker, the canonical
// store already holds the full tree under $OOM_STORE_ROOT/<checkout_path>/.
//
// Putting checkout/create on the submitter (instead of here) keeps the file manifest —
// sha256 + size per file, which for a texture-heavy Bella scene is huge — out of job
// settings and off the worker's command line. The worker doesn't need the manifest
// because Shaman is content-addressed: every file under the checkout is, by
// construction, the file the submitter uploaded.
//
// ---- Worker env (systemd) ---------------------------------------------------
// /etc/systemd/system/flamenco-worker.service → Environment=…
//
//   OOM_STORE_ROOT      — The directory under which Shaman resolves <checkout_path>.
//                         Must exactly match `shaman.checkoutPath` in flamenco-manager.yaml
//                         (NOT just the share mount — Flamenco's default layout puts
//                         checkouts at <share>/jobs/<checkout_path>, so the typical
//                         value here is e.g. /mnt/oomerfarm/flamenco/jobs — verify on
//                         worker by running ls against your share root, e.g.:
//                           ls /mnt/oomerfarm/flamenco
//                         → whichever subdir holds submitted job checkouts (usually
//                         'jobs') is the right value's tail. If you've already
//                         submitted one job via rhino_bella, pick any subdir there and
//                         `readlink -f <subdir>/*/*/*` — everything before the first
//                         two-char sha shard is OOM_BLOB_STORE; the bit up to (but
//                         not including) your project name is OOM_STORE_ROOT.
//   OOM_RENDER_ROOT     — Where rendered outputs land on the share. Separate root
//                         from OOM_STORE_ROOT so renders never pollute a Shaman
//                         checkout. Typical sibling path, e.g.
//                           /mnt/oomerfarm/flamenco/renders
//   OOM_BLOB_STORE      — Shaman's content-addressed blob root, i.e. the directory
//                         that checkout symlinks actually resolve under. Shaman places
//                         blobs inside a 'stored/' subdir of shaman.fileStorePath, so
//                         this is typically e.g.
//                           /mnt/oomerfarm/flamenco/file-store/stored
//                         Note: fileStorePath is often defaulted and missing from
//                         flamenco-manager.yaml — verify the real path on a worker:
//                           readlink -f "$OOM_STORE_ROOT"/<any-job>/*/<any-file> | head -1
//                         The portion of that path before the two-char sha shard
//                         is OOM_BLOB_STORE.
//   OOM_TMP_DISK        — e.g. /tmp/oomerfarm (fast local scratch; holds the blob cache
//                         under file-store/stored/ — mirroring the share's Shaman
//                         layout — plus input trees under checkouts/ and render
//                         output trees under renders/).
//   FFMPEG_PATH         — e.g. /opt/oomerfarm/bin/ffmpeg-linux-amd64
//
// Bella version is a per-job setting (pulldown) rather than worker env — every worker is expected
// to have every listed version installed at /opt/oomerfarm/bin/bella-<ver>-cli/bella_cli.
//
// ---- Runtime note -----------------------------------------------------------
// The JS itself runs inside the flamenco-manager goja VM where `process` is undefined —
// so env is NEVER read from JS. All vars are expanded by /bin/sh on the worker at task-exec time.
// ---- Naming map (same concept across languages) ----------------------------
//   Concept           Python              JS (local)        Shell                Shaman API
//   ───────           ──────              ──────────        ─────                ──────────
//   checkout id       checkout_path       checkoutPath      CHECKOUT_PATH        checkoutPath
//   local inputs      —                   —                 LOCAL_CHECKOUT       —
//   local outputs     —                   —                 LOCAL_RENDER         —
// LOCAL_CHECKOUT = $OOM_TMP_DISK/checkouts/$CHECKOUT_PATH   (hard links to blob cache)
// LOCAL_RENDER   = $OOM_TMP_DISK/renders/$CHECKOUT_PATH     (real files bella writes)

function shQuote(s) {
    return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

// Reject path-traversal, absolute paths, and weird filename chars before they reach the
// shell / filesystem. shQuote stops shell injection; this stops "../../etc" style escapes.
function validateRelPath(value, label) {
    const s = String(value === null || value === undefined ? "" : value);
    if (s.length === 0) {
        throw new Error(label + " is required");
    }
    if (s.length > 255) {
        throw new Error(label + " too long (max 255)");
    }
    if (s.indexOf("\\") !== -1 || s.indexOf("\0") !== -1) {
        throw new Error(label + " contains disallowed characters");
    }
    if (s.charAt(0) === "/") {
        throw new Error(label + " must be a relative path (no leading /)");
    }
    const parts = s.split("/");
    for (let i = 0; i < parts.length; i++) {
        const seg = parts[i];
        if (seg === "" || seg === "." || seg === "..") {
            throw new Error(label + " contains empty, '.', or '..' segment: " + s);
        }
        if (!/^[A-Za-z0-9._-]+$/.test(seg)) {
            throw new Error(label + " segment has invalid characters: " + seg);
        }
    }
}

const JOB_TYPE = {
    label: "simple-bella-render",
    settings: [
        {
            key: "checkout_path",
            type: "string",
            description: "Shaman checkoutPath — the relative id the submitter passed to /api/v3/shaman/checkout/create. Conventionally '{project}/{scene_base}/{YYYYMMDD_HHMMSS}', e.g. 'harvey_darwin/cowbell/20260416_120000'. Segments must match [A-Za-z0-9._-].",
            required: true,
        },
        {
            key: "bella_scene",
            type: "string",
            description: "Bella scene file",
            default: "simple.bsx",
        },
        {
            key: "bella_version",
            type: "string",
            description: "Bella CLI version (must be installed at /opt/oomerfarm/bin/bella-<ver>-cli/)",
            choices: ["25.3.0", "24.6.0"],
            default: "25.3.0",
        },
    ],
};

// Worker-side library: sourced at the top of every command. Defines oom_fetch /
// oom_push and asserts OOM_STORE_ROOT + OOM_RENDER_ROOT + OOM_BLOB_STORE +
// OOM_TMP_DISK. If missing or unreadable, `set -e` aborts the command with a
// clear "No such file" from /bin/sh.
const OOM_SYNC_LIB = "/opt/oomerfarm/lib/oom-sync.sh";

function compileJob(job) {
    const settings = job.settings;

    // Validate user-controlled path settings BEFORE they reach any shell string or
    // the Shaman API. A traversal-y checkout_path would otherwise let the worker
    // push/fetch outside the canonical store.
    const checkoutPath = String(settings.checkout_path || "");
    validateRelPath(checkoutPath, "checkout_path");
    const scene = settings.bella_scene || "simple.bsx";
    validateRelPath(scene, "bella_scene");

    // checkoutPath / scene / sceneBaseName are all validated against [A-Za-z0-9._-]
    // per segment, so inlining them in double-quoted shell context is injection-safe.
    const sceneBaseName = scene.replace(/\.[^/.]+$/, "");
    const thumbScale = "800:-1";
    const bellaVersion = settings.bella_version || "25.3.0";
    const bellaCli = "/opt/oomerfarm/bin/bella-" + bellaVersion + "-cli/bella_cli";

    // Every command's opening: strict shell, source the transport lib (which
    // asserts OOM_STORE_ROOT / OOM_RENDER_ROOT / OOM_BLOB_STORE / OOM_TMP_DISK
    // and provides oom_fetch/oom_push), then bind the three path vars used by
    // every subsequent line.
    const head = [
        "set -euo pipefail",
        ". " + OOM_SYNC_LIB,
        'CHECKOUT_PATH="' + checkoutPath + '"',
        'LOCAL_CHECKOUT="$OOM_TMP_DISK/checkouts/$CHECKOUT_PATH"',
        'LOCAL_RENDER="$OOM_TMP_DISK/renders/$CHECKOUT_PATH"',
    ].join("\n");

    // 1. Materialize: pull checkout tree → local NVMe as hard links into the
    // blob cache, and pre-create the render scratch dir so bella's -od never
    // hits ENOENT.
    const materializeScript = [
        head,
        'oom_fetch "$CHECKOUT_PATH" "$LOCAL_CHECKOUT"',
        'mkdir -p "$LOCAL_RENDER"',
    ].join("\n");

    // 2. Bella render: reads inputs from LOCAL_CHECKOUT, writes outputs to
    // LOCAL_RENDER (disjoint trees). exec replaces the shell (one less process).
    const renderScript = [
        head,
        "exec stdbuf -oL -eL " + shQuote(bellaCli) +
            ' "-i:${LOCAL_CHECKOUT}/' + scene + '"' +
            ' "-od:${LOCAL_RENDER}"' +
            ' "-on:' + sceneBaseName + '"' +
            " 2>&1",
    ].join("\n");

    // 3. Publish: one rsync of the whole render tree → $OOM_RENDER_ROOT. No
    // conditionals, no file-sifting — whatever bella wrote (PNG + any multipass
    // subdirs) lands under the same path. Trailing slash on LOCAL_RENDER/ means
    // "contents of", flattening out one level of nesting.
    const publishScript = [
        head,
        'oom_push "$LOCAL_RENDER/" "$CHECKOUT_PATH"',
    ].join("\n");

    // 4. Thumbnail: ffmpeg PNG → preview.jpg, push to $OOM_RENDER_ROOT.
    // Emitted as a blender-render command type so flamenco-worker's "Saved:"
    // regex fires and surfaces the preview in the web GUI.
    const thumbnailScript = [
        "set -euo pipefail",
        ': "${FFMPEG_PATH:?FFMPEG_PATH not set in worker env}"',
        ". " + OOM_SYNC_LIB,
        'CHECKOUT_PATH="' + checkoutPath + '"',
        'LOCAL_RENDER="$OOM_TMP_DISK/renders/$CHECKOUT_PATH"',
        'PREVIEW="$LOCAL_RENDER/preview.jpg"',
        '"$FFMPEG_PATH" -i "$LOCAL_RENDER/' + sceneBaseName + '.png" -vf scale=' + thumbScale + ' -q:v 5 "$PREVIEW" -y',
        'oom_push "$PREVIEW" "$CHECKOUT_PATH"',
        'printf "\\nSaved: \'%s\'\\n" "$OOM_RENDER_ROOT/$CHECKOUT_PATH/preview.jpg"',
        "sleep 2",
    ].join("\n");

    // Single task, four commands. Flamenco runs commands of one task serially on
    // one worker — that's what pins bella's local outputs to the same node that
    // publish/thumbnail later read from.
    const renderTask = author.Task("Render single frame", "misc");
    renderTask.addCommand(author.Command("exec", {
        exe: "/bin/sh",
        args: ["-c", materializeScript],
    }));
    renderTask.addCommand(author.Command("exec", {
        exe: "/bin/sh",
        args: ["-c", renderScript],
    }));
    renderTask.addCommand(author.Command("exec", {
        exe: "/bin/sh",
        args: ["-c", publishScript],
    }));
    renderTask.addCommand(author.Command("blender-render", {
        exe: "/bin/sh",
        frames: "1",
        blendfile: "-c",
        args: [thumbnailScript],
    }));
    job.addTask(renderTask);
}
