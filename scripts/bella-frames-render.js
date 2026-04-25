// Deploy next to flamenco-manager: /opt/oomerfarm/scripts/bella-frames-render.js
//
// Multi-.bsz sequence: one job, one task per frame. The submitter unpacks all
// .bsz into one Shaman tree (shared res/); each task renders one .bsx path (basename
// matches its .bsz). Local scratch: ``$OOM_TMP_DISK/renders/<checkout_path>/`` for all
// frames in the job (unique ``-on``/PNG basenames per task; no frames_work/…). Share:
// same rel path on ``$OOM_RENDER_ROOT``.
//
// SYNC: With simple-bella-render.js: materialize, bella -on (leaf basename), oom_sync.

function shQuote(s) {
    return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

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

const OOM_SYNC_LIB = "/opt/oomerfarm/lib/oom-sync.sh";

const JOB_TYPE = {
    label: "bella-frames-render",
    settings: [
        {
            key: "checkout_path",
            type: "string",
            description:
                "Shaman checkoutPath. One merged tree: shared res/; each bella_scene is <stem>.bsx at repo root, matching that frame's .bsz name.",
            required: true,
        },
        {
            key: "bella_version",
            type: "string",
            description: "Bella CLI version (must be installed at /opt/oomerfarm/bin/bella-<ver>-cli/)",
            choices: ["25.3.0", "24.6.0"],
            default: "25.3.0",
        },
        {
            key: "bella_frames_json",
            type: "string",
            description:
                "JSON: bella_scene, output_tag, publish_stem. Local render: one dir per job " +
                "…/renders/<checkout_path>/; PNGs are unique per frame. output_tag: task id only (not a path on disk).",
            required: true,
        },
    ],
};

function _sceneOutputBaseName(scene) {
    const s = String(scene);
    const leaf = s.split("/").pop() || s;
    return leaf.replace(/\.[^/.]+$/, "");
}

function _parseBellaFramesJson(raw) {
    const s = String(raw === null || raw === undefined ? "" : raw).trim();
    if (!s) {
        throw new Error("bella_frames_json is required");
    }
    const arr = JSON.parse(s);
    if (!Array.isArray(arr) || arr.length === 0) {
        throw new Error("bella_frames_json must be a non-empty JSON array");
    }
    return arr;
}

function _buildOneFrameTask(
    author,
    checkoutPath,
    scene,
    outputTag,
    publishStem,
    bellaVersion
) {
    validateRelPath(scene, "bella_scene");
    validateRelPath(outputTag, "output_tag");
    validateRelPath(publishStem, "publish_stem");

    const sceneBaseName = _sceneOutputBaseName(scene);
    const thumbScale = "800:-1";
    const bellaCli = "/opt/oomerfarm/bin/bella-" + bellaVersion + "-cli/bella_cli";
    // One local output dir for the whole job; PNGs are named by -on (per-frame unique).
    const renderRoot = 'LOCAL_FRAME_RENDER="$OOM_TMP_DISK/renders/$CHECKOUT_PATH"';

    const head = [
        "set -euo pipefail",
        ". " + OOM_SYNC_LIB,
        'CHECKOUT_PATH="' + checkoutPath + '"',
        'LOCAL_CHECKOUT="$OOM_TMP_DISK/checkouts/$CHECKOUT_PATH"',
        renderRoot,
    ].join("\n");

    const materializeScript = [head, 'oom_fetch "$CHECKOUT_PATH" "$LOCAL_CHECKOUT"', 'mkdir -p "$LOCAL_FRAME_RENDER"'].join(
        "\n"
    );

    const renderScript = [
        head,
        "exec stdbuf -oL -eL " +
            shQuote(bellaCli) +
            ' "-i:${LOCAL_CHECKOUT}/' +
            scene +
            '"' +
            ' "-od:${LOCAL_FRAME_RENDER}"' +
            ' "-on:' +
            sceneBaseName +
            '"' +
            " 2>&1",
    ].join("\n");

    // Share path: …/renders/<checkout_path>/<publishStem>.png (matches simple-bella placement)
    const publishScript = [
        "set -euo pipefail",
        ". " + OOM_SYNC_LIB,
        'CHECKOUT_PATH="' + checkoutPath + '"',
        'LOCAL_CHECKOUT="$OOM_TMP_DISK/checkouts/$CHECKOUT_PATH"',
        'LOCAL_FRAME_RENDER="$OOM_TMP_DISK/renders/$CHECKOUT_PATH"',
        ': "${OOM_RENDER_ROOT:?OOM_RENDER_ROOT not set in worker env}"',
        'DEST_DIR="$OOM_RENDER_ROOT/$CHECKOUT_PATH"',
        'mkdir -p "$DEST_DIR"',
        "cp -f \"$LOCAL_FRAME_RENDER/" + sceneBaseName + ".png\" \"$DEST_DIR/" + publishStem + '.png"',
    ].join("\n");

    // Previews for Flamenco only — not beside final PNGs (see _flamenco_ui/ parallel tree)
    const thumbnailScript = [
        "set -euo pipefail",
        ': "${FFMPEG_PATH:?FFMPEG_PATH not set in worker env}"',
        ". " + OOM_SYNC_LIB,
        'CHECKOUT_PATH="' + checkoutPath + '"',
        'LOCAL_FRAME_RENDER="$OOM_TMP_DISK/renders/$CHECKOUT_PATH"',
        ': "${OOM_RENDER_ROOT:?}"',
        'UI_PREVIEW_DIR="$OOM_RENDER_ROOT/_flamenco_ui/$CHECKOUT_PATH"',
        "mkdir -p \"$UI_PREVIEW_DIR\"",
        '"$FFMPEG_PATH" -i "$LOCAL_FRAME_RENDER/' + sceneBaseName + '.png" -vf scale=' + thumbScale + ' -q:v 5 "$UI_PREVIEW_DIR/' + publishStem + '.preview.jpg" -y',
        'printf "\\nSaved: \'%s\'\\n" "$UI_PREVIEW_DIR/' + publishStem + '.preview.jpg"',
        "sleep 2",
    ].join("\n");

    const label = "Frame " + publishStem;
    const t = author.Task(label, "misc");
    t.addCommand(
        author.Command("exec", {
            exe: "/bin/sh",
            args: ["-c", materializeScript],
        })
    );
    t.addCommand(
        author.Command("exec", {
            exe: "/bin/sh",
            args: ["-c", renderScript],
        })
    );
    t.addCommand(
        author.Command("exec", {
            exe: "/bin/sh",
            args: ["-c", publishScript],
        })
    );
    t.addCommand(
        author.Command("blender-render", {
            exe: "/bin/sh",
            frames: "1",
            blendfile: "-c",
            args: [thumbnailScript],
        })
    );
    return t;
}

function compileJob(job) {
    const settings = job.settings;
    const checkoutPath = String(settings.checkout_path || "");
    validateRelPath(checkoutPath, "checkout_path");
    const bellaVersion = settings.bella_version || "25.3.0";
    const rawFrames = settings.bella_frames_json;
    const list = _parseBellaFramesJson(rawFrames);
    for (let i = 0; i < list.length; i++) {
        const row = list[i] || {};
        const scene = row.bella_scene;
        const tag = row.output_tag;
        const pstem = String(row.publish_stem || row.output_tag || "").trim();
        if (!scene || !tag) {
            throw new Error("bella_frames_json[" + i + "] must have bella_scene and output_tag");
        }
        if (!pstem) {
            throw new Error("bella_frames_json[" + i + "] must have publish_stem (or output_tag)");
        }
        job.addTask(
            _buildOneFrameTask(author, checkoutPath, String(scene), String(tag), pstem, bellaVersion)
        );
    }
}
