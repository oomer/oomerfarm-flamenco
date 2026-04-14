const JOB_TYPE = {
    label: "Simple Bella Render",
    settings: [
        { key: "bsz", type: "string", subtype: "file_path", required: true, 
          description: "bsz file to render"},
        { key: "outdir", type: "string", subtype: "dir_path", required: true, default: "/mnt/oomerfarm/flamenco",
          description: "Output dir for rendered images"},
        { 
            key: "ext", 
            type: "string", 
            default: ".png", 
            description: "Output File Format",
            choices: [".png", ".jpg", ".bmp", ".tga", ".tif", ".iff", ".dpx", ".exr", ".hdr"]
        },
        { key: "override_res", label: "Use Custom Resolution?", type: "bool", default: false },
        { key: "resx", label: "↳ Custom Width", type: "int32", default: 1920 },
        { key: "resy", label: "↳ Custom Height", type: "int32", default: 1080 },
    ]
};

function compileJob(job) {
    const settings = job.settings;
   
    const managerUrl = "http://10.88.0.1:8080"; 
    const remoteBsz = settings.bsz;
    const localBsz = "/tmp/render_job.bsz";
    const localOutDir = "/tmp/bella_out/";
    const remoteOutDir = settings.outdir;

    const bszFileName = remoteBsz.split('/').pop(); 
    const baseName = bszFileName.replace(/\.[^/.]+$/, "");
    const extFragment = `-pf:nnbeautyPass.outputExt="${settings.ext}";`;

    let resArg = "";
    if (settings.override_res) {
        resArg = `-res:${settings.resx}x${settings.resy}`;
    }
    const renderFile = `${localOutDir}${baseName}${settings.ext}`;

    const setupTask = author.Task("Copy assets locally", "file-management");
    setupTask.addCommand(author.Command("exec", {
        exe: "/bin/sh",
        args: ["-c", `mkdir -p ${localOutDir} && cp "${remoteBsz}" "${localBsz}"`]
    }));
    job.addTask(setupTask);

    const bellaTask = author.Task("Bella Render", "misc");
    bellaTask.addDependency(setupTask); 

    const bellaCmd = `stdbuf -oL -eL /usr/local/bin/bella_cli "-i:${localBsz}" "-od:${localOutDir}" "-on:${baseName}" '${extFragment}' ${resArg}`;
    bellaTask.addCommand(author.Command("exec", {
        exe: "/bin/sh",
        args: ["-c", `${bellaCmd} 2>&1`]
    }));

    const makeThumb = `/home/oomerfarm/tools/ffmpeg-linux-amd64 -i "${renderFile}" -vf scale=800:-1 -q:v 5 /tmp/preview.jpg -y`;
    bellaTask.addCommand(author.Command("blender-render", {
        "blendfile": "-c", 
        "frames": "1",
        "exe": "/bin/sh",
        "args": [
            `${makeThumb} && printf "\\nSaved: '/tmp/preview.jpg'\\n" && sleep 2`
        ],
    }));
    
    job.addTask(bellaTask); 

    const cleanupTask = author.Task("Upload to /mnt/oomerfarm/flamenco/...", "file-management");
    cleanupTask.addDependency(bellaTask);
    cleanupTask.addCommand(author.Command("exec", {
        exe: "/bin/sh",
        args: ["-c", `cp "${renderFile}" "${remoteOutDir}/" && rm -rf ${localOutDir} ${localBsz}`]
    }));
    job.addTask(cleanupTask);
}
