# Overview
The Ax Framework is a free and open-source tool utilized by Bug Hunters and Penetration Testers to efficiently operate in multiple cloud environments. It helps build and deploy repeatable infrastructure tailored for offensive security purposes.

Ax includes a set of Packer [Provisioner](https://github.com/attacksurge/ax/tree/main/images/provisioners) files to choose from, or you can [create your own](https://ax-framework.gitbook.io/wiki/fundamentals/bring-your-own-provisioner) (recommended).

Whichever [Packer](https://www.packer.io/) Provisioner you select, Ax installs your tools of choice into a "base image". Then using that image, you can deploy fleets of fresh instances (cloud hosted compute devices). Using this image, you can connect and immediately access a wide range of tools useful for both Bug Hunting and Penetration Testing.

Various [Ax Utility Scripts](https://ax-framework.gitbook.io/wiki/fundamentals/ax-utility-scripts) streamline tasks like spinning up and deleting fleets of instances, parallel command execution and file transfers, instance and image backups, and many other operations.

With the power of ephemeral infrastructure, most of which is automated, you can easily create many disposable instances. Ax enables the distribution of scanning operations for arbitrary binaries and scripts (the full list varies based on your chosen [Provisioner](https://github.com/attacksurge/ax/tree/main/images/provisioners)). Once installed and configured, Ax allows you to spread a large scan across 50-100+ instances within minutes, delivering rapid results. This process is known as [ax scan](https://ax-framework.gitbook.io/wiki/fundamentals/scans) (axiom-scan).

Ax attempts to follow the Unix philosophy by providing building blocks that allow users to easily orchestrate one or many cloud instances. This flexibility enables the creation of continuous scanning pipelines and the execution of general, one-off, highly parallelized workloads.

Currently, Digital Ocean, IBM Cloud, Linode, Azure and AWS are officially supported cloud providers.

# Installation
## Docker

This will create a docker container, initiate [`axiom-configure`](https://ax-framework.gitbook.io/wiki/fundamentals/ax-utility-scripts#ax-configure) and [`axiom-build`](https://ax-framework.gitbook.io/wiki/fundamentals/ax-utility-scripts#axiom-build) and then drop you out of the docker container. Once the [Packer](https://www.packer.io/) image is successfully created, you will likely need to re-exec into your docker container via `docker exec -it $container_id zsh`.
```
docker exec -it $(docker run -d -it --platform linux/amd64 ubuntu:20.04) sh -c "apt update && apt install git -y && git clone https://github.com/attacksurge/ax/ ~/.axiom/ && cd && .axiom/interact/axiom-configure --setup"
```

## Easy Install

You should use an OS that supports our [easy install](https://ax-framework.gitbook.io/wiki/overview/installation-guide#operating-systems-supported). <br>
For Linux systems you will also need to install the newest versions of all packages beforehand `sudo apt dist-upgrade`. <br>
```
bash <(curl -s https://raw.githubusercontent.com/attacksurge/ax/master/interact/axiom-configure) --setup
```

If you have any problems with this installer, or if using an unsupported OS please refer to [Installation](https://ax-framework.gitbook.io/wiki/overview/installation-guide#operating-systems-supported).


## Operating Systems Supported
| OS         | Supported | Easy Install  | Tested        | 
|------------|-----------|---------------|---------------|
| Ubuntu     |    Yes    | Yes           | Ubuntu 20.04  |
| Kali       |    Yes    | Yes           | Kali 2021.3   |
| Debian     |    Yes    | Yes           | Debian 10     |
| Windows    |    Yes    | Yes           | WSL w/ Ubuntu |
| MacOS      |    Yes    | Yes           | MacOS 11.6    |
| Arch Linux |    Yes    | No            | Yes           |


