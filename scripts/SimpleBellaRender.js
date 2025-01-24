const JOB_TYPE = {
    label: "Simple Bella Render",
    settings: [
        { key: "bsz", type: "string", subtype: "file_path", required: true, 
          description: "bsz file to render"},
        { key: "outdir", type: "string", subtype: "dir_path", required: true, 
          description: "Output dir for rendered images"},
        { key: "resx", type: "int32", default: 800 },
        { key: "resy", type: "int32", default: 800 },
    ]
};

function compileJob(job) {
    const settings = job.settings;
    let bsz = JSON.stringify(job.settings.bsz)
    bsz = "-i:"+bsz;
    //bsz = "-i:"+bsz.replace(/\/\/\.\.\/\.\.\/Volumes/, "/mnt"); 
    bsz = bsz.replace(/['"]/g, '');
    print("bsz",bsz)  

    let outdir = JSON.stringify(job.settings.outdir)
    outdir = "-od:"+outdir;
    //outdir = "-od:"+outdir.replace(/\/\/\.\.\/\.\.\/Volumes/, "/mnt"); 
    outdir = outdir.replace(/['"]/g, '');
    print("outdir",outdir)  

    const bellaTask = author.Task("bella", "misc");
    bellaTask.addCommand(author.Command("exec", 
    { exe: "/usr/local/bin/bella_cli",
        args: [ bsz, outdir, "-res:200x200"],
        } ));
    job.addTask(bellaTask);
}