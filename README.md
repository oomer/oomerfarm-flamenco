# Guided scripts for deploying a Flamenco renderfarm 

[ WORK IN PROGRESS ]
[ ALPHA release v0.1 ]

>#### A family of helpers scripts for DIY renderfarms to take advantage of cheap hourly rates at any cloud compute provider

### oomerfarm-flamenco adds https://flamenco.blender.org
- Flamenco provides the actual renderfarm functionality while these scripts provide a network topology with storage and security to complement it.

### Renderfarm have a lot of moving parts and these 4 scripts break down the task into manangeable chunks

<span style="color:cyan;">bolstersecurity.sh</span> = manage VPN security keys

<span style="color:cyan;">bootstrapfarm.sh</span> = prep network storage and flamenco-manager

<span style="color:cyan;">bootstrapworker.sh</span> = run on each worker to prep flamenco-worker

<span style="color:cyan;">bridgefarm.sh</span> = user connect to VPN

## Security notes ( always audit the code )

- Uses [Nebula](https://github.com/slackhq/nebula) to overlay a private network across the internet to hide your (**http**)  flamenco-manager and (**smb**) network storage access.
- servers and workers enforce SELinux and any traffic other than 22/tcp and 42042/udp are dropped by the firewall
- Nebula group access limits mean the "farm" workers cannot upstream connect to your laptop
- Your workstation's connection is alive only while the **bridgefarm.sh** is running. Keep terminal/cli/cmd window off to the side. Yes a proper app would be more efficient, if you want one use (Tailscale)[https://tailscale.com] :)

> Note while bolstersecurity.sh and bridgefarm.sh run on Mac/Win/Linux, flamenco-manager and and flamenco-worker will only be deployed via bootstrapfarm.sh and bootstrapworker.sh on Linux.

---
## Computers Needed
- <span style="color:cyan;">Computer A</span> => Mac/Win/Linux Blender workstation
- <span style="color:cyan;">Computer B</span> => a Alma/Rocky 8.x/9.x Linux server: 
    - Doesn't render, just adds network storage and dispatches jobs
    - [RECOMMENDED] run a a cheap monthly server [see lowendtalk.com](https://lowendtalk.com/categories/offers)
    - OR run on a mini pc at home and port forward [42042] on your router 
- <span style="color:cyan;">Computer 1-100</span> => cpu/gpu Alma/Rocky 8.x/9.x Linux hourly rentals [examples](https://tensordock.com/)
    - OR Add your local computers 
---

## Run scripts in terminal/cli 
- bash scripts run natively on MacOS/Linux
- Windows requires [git-scm](https://git-scm.com) to get bash

1. <span style="color:green;">**bash bolstersecurity.sh**</span> on <span style="color:cyan;">Computer A</span> creating VPN credentials  

        - generates keys for Nebula overlay network
        - put encrypted keys on Google Drive, share publicly, copy link
2. <span style="color:green;">**bash bootstrapfarm.sh**</span> on <span style="color:cyan;">Computer B</span>
        
        - joins Nebula overlay network
        - launches flamenco-manager
        - provides network storage 
3. <span style="color:green;">**bash bootstrapworker.sh**</span> on <span style="color:cyan;">Computer 1-100</span> hourly rentals

        - joins Nebula overlay network
        - launches flamenco-worker
        - [NOTE] ensure worker names are numerically unique workerxxx to avoid IP address clash
        - [SECURITY NOTE] each worker has ALL worker keys to simplify mass deployment. They are trusted as a group. 

4. <span style="color:green;">**bash bridgefarm.sh**</span> on <span style="color:cyan;">Computer A</span>. Connect to http://10.88.01:8080 , from there download add-on, launch Blender, install add-on, submit job via Outputs section. 
        
        - joins Nebula overlay network
5. <span style="color:green;">Blender</span> 

        - mount smb://10.88.0.1/oomerfarm MacOS/Linux
        - mount \\10.88.0.1\oomerfarm Windows
                - map this as the O: drive
                - edit /home/oomerfarm/flamenco-manager.yaml if you map to a different letter 

        - http://10.88.0.1:8080 from your workstation
        - Blender install Flamenco add-on from webpage
        - Set Manager URL to http://10.88.0.1:8080 

        - In Output tab -> Flamenco  submit 
        - get your images


## Summary

4 bash scripts, all starting with the letter ***b*** to empower your personal renderfarm.

    - bolstersecurity.sh -> Mac/Win/Linux Desktop
    - bootstrapfarm.sh -> Linux Server
    - bootstrapworker.sh -> Linux Worker
    - bridgefarm.sh -> Mac/Win/Linux Desktop




## Compute Charges
- You will be charged the the hour or by the month even if you forget to destroy your Virtual Machines. Remember to destroy.
- [TODO] Add auto destroy timer ( useful so far only on GCP )

## Security note
- not all cloud vendors scrub their drives after each rental allowing the next renter to possible retrieve passwords and keys present on the disk
- [TODO] Add the ability to encrypt the disk at rest or to wipe the keys before rental expiry. 