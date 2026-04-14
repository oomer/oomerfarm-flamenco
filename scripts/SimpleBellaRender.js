const JOB_TYPE = {
    label: "Simple Bella Render",
    settings: [
        { key: "bsz", type: "string", subtype: "file_path", required: true, 
          description: "bsz file to render"},
        { key: "outdir", type: "string", subtype: "dir_path", required: true, default: "/mnt/oomerfarm/flamenco",
          description: "Output dir for rendered images"},
        { key: "resx", type: "int32", default: 800 },
        { key: "resy", type: "int32", default: 800 },
    ]
};

function compileJob(job) {
    const settings = job.settings;
    const bszArg = "-i:" + settings.bsz;
    const outdirArg = "-od:" + settings.outdir;
    const resArg = `-res:${settings.resx}x${settings.resy}`;
	
    const bellaTask = author.Task("bella", "misc");
    bellaTask.addCommand(author.Command("exec", 
    { exe: "/usr/local/bin/bella_cli",
        args: [ bszArg, outdirArg, resArg],
        } ));
    job.addTask(bellaTask);
}
