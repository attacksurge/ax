<p align="center">
<a href="https://ax-framework.gitbook.io/wiki" target="_blank"> 
<img src="https://raw.githubusercontent.com/attacksurge/ax/Exoscale/screenshots/axbanner.png"/>
</a> 
</p>

<p align="center">

  <a href="https://twitter.com/0xtavian">
    <img src="https://img.shields.io/badge/Follow-@0xtavian-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white&labelColor=222222">
  </a>
  &nbsp;&nbsp;

  <a href="https://ax-framework.gitbook.io/wiki">
    <img src="https://img.shields.io/badge/Documentation-2E2E2E?style=for-the-badge&logo=readthedocs&logoColor=white">
  </a>
  &nbsp;&nbsp;

  <a href="modules/">
    <img src="https://img.shields.io/badge/Modules-2E2E2E?style=for-the-badge&logo=json&logoColor=white">
  </a>
  &nbsp;&nbsp;

  <a href="https://discord.gg/nGqfRh9tdT">
    <img src="https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white">
  </a>

  <hr style="width:60%; border:0; border-top:1px solid #333;">
</p>


**Ax Framework is a next-generation cloud automation system for offensive security and distributed scanning.**  
Designed to scale with your workflow, Ax orchestrates custom tools, scripts, and scans across cloud fleets — with zero friction.

- **Modular scanning** with support for tools like `nmap`, `ffuf`, `gowitness`, `nuclei`, and more.  
- **Fleet-wide execution** of arbitrary binaries or scripts, with support for 9 major cloud providers: AWS, Azure, DigitalOcean, GCP, Hetzner, IBM Cloud, Scaleway, Exoscale, and Linode.  
- **Custom JSON-based modules** define the base command structure and expose variables for runtime injection.  
- **Automatic interpolation** of user-provided arguments into modules to build the final command on each instance.  
- **Smart input distribution**, including automatic splitting of target lists, wordlists, and configuration files.  
- **Multi-provider flexibility**, allowing you to switch between clouds effortlessly.


# Overview 
Ax Framework is a free and open-source tool utilized by Bug Hunters and Penetration Testers to efficiently operate in multiple cloud environments. It helps build and deploy repeatable infrastructure tailored for offensive security purposes.

Ax includes a set of Packer Provisioner files to choose from ([JSON](https://github.com/attacksurge/ax/tree/master/images/json/provisioners) or [HCL](https://github.com/attacksurge/ax/tree/master/images/pkr.hcl/provisioners)), or you can [create your own](https://ax-framework.gitbook.io/wiki/fundamentals/bring-your-own-provisioner) (recommended).

Whichever [Packer](https://www.packer.io/) Provisioner you select, Ax installs your tools of choice into a "base image". Then using that image, you can deploy fleets of fresh instances (cloud hosted compute devices). When building an image using the [Default](https://github.com/attacksurge/ax/blob/master/images/pkr.hcl/provisioners/default.pkr.hcl) Provisioner, you can connect and immediately access a wide range of tools useful for both Bug Hunting and Penetration Testing.

Various [Ax Utility Scripts](https://ax-framework.gitbook.io/wiki/fundamentals/ax-utility-scripts) streamline tasks like spinning up and deleting fleets of instances, parallel command execution and file transfers, instance and image backups, and many other operations.

Ax Framework leverages the power of ephemeral, automated infrastructure to make cloud-based scanning operations fast and efficient. With Ax, you can quickly spin up disposable cloud instances, distribute your scanning workloads, and manage large-scale operations with ease. The framework supports running arbitrary binaries and scripts, determined by the specific Packer Provisioner you select and [Module](https://ax-framework.gitbook.io/wiki/fundamentals/scans/modules) you use.

Once Ax is set up and configured, you can deploy a fleet of 50-100+ instances in just minutes, distribute a highly parallelized scan against a large scope of targets, and deliver rapid, reliable results. This functionality is known as [ax scan](https://ax-framework.gitbook.io/wiki/fundamentals/scans).

Ax attempts to follow the Unix philosophy by providing building blocks that allow users to easily orchestrate one or many cloud instances. This flexibility enables the creation of continuous scanning pipelines and the execution of general, one-off, highly parallelized workloads.

Currently Digital Ocean, IBM Cloud, Linode, Azure, AWS, Hetzner, GCP and Scaleway are officially supported cloud providers.

![](https://raw.githubusercontent.com/attacksurge/ax/refs/heads/master/screenshots/axiom-fleet.gif)

# Resources

-   [Introduction](https://ax-framework.gitbook.io/wiki#overview)
-   [Existing Users](https://ax-framework.gitbook.io/wiki/overview/existing-users)
-   [the Ax Controller](https://ax-framework.gitbook.io/wiki/overview/ax-controller)
-   [How it Works](https://ax-framework.gitbook.io/wiki/overview/how-it-works)
-   [Installation Instructions](https://ax-framework.gitbook.io/wiki/overview/installation-guide)
    -   [Docker Install](#docker)
    -   [Easy Install](#easy-install)
    -   [Manual Install](https://ax-framework.gitbook.io/wiki/overview/installation-guide#manual)
-   [Fleets](https://ax-framework.gitbook.io/wiki/fundamentals/fleets)
-   [Scans](https://ax-framework.gitbook.io/wiki/fundamentals/scans)
-   [Modules](https://ax-framework.gitbook.io/wiki/fundamentals/scans/modules)
      - [Merging and Module Extensions](https://ax-framework.gitbook.io/wiki/fundamentals/scans/modules/merging-and-module-extensions)
      - [Adding Simple Modules](https://ax-framework.gitbook.io/wiki/fundamentals/scans/modules/adding-simple-modules)
      - [Adding One-Shot Modules](https://ax-framework.gitbook.io/wiki/fundamentals/scans/modules/adding-one-shot-modules)
-   [SBOMs](https://ax-framework.gitbook.io/wiki/overview/ax-controller#sbom)
  
# Credits

Digital Ocean is still our best and most supported cloud provider. If you're signing up for a new Digital Ocean account, [please use this link](https://m.do.co/c/541daa5b4786) for a $200 free credit!
<p align="center">
<a href="https://m.do.co/c/541daa5b4786" target="_blank"> 
<img src="https://raw.githubusercontent.com/attacksurge/ax/master/screenshots/digitalocean.png"/>
</a> 
</p>

IBM Cloud is still our best supported business provider! If you're signing up for a new IBM Cloud account, [please use this link](https://cloud.ibm.com/docs/overview?topic=overview-tutorial-try-for-free) for $200 free credit!
<p align="center">
<a href="https://cloud.ibm.com/docs/overview?topic=overview-tutorial-try-for-free" target="_blank"> 
<img src="https://raw.githubusercontent.com/attacksurge/ax/master/screenshots/ibm_cloud.png"/>
</a> 
</p>

Linode is an absoutely fantastic cloud provider and fully supported! If you're signing up for a new Linode account, [please use this link](https://www.linode.com/lp/refer/?r=71f79f7e02534d6f673cbc8a17581064e12ac27d) for $100 free credit!
<p align="center">
<a href="https://www.linode.com/lp/refer/?r=71f79f7e02534d6f673cbc8a17581064e12ac27d" target="_blank"> 
<img src="https://raw.githubusercontent.com/attacksurge/ax/master/screenshots/linode.png"/>
</a> 
</p>

<p align="center">
<a href="https://azure.com" target="_blank"> 
<img src="https://raw.githubusercontent.com/attacksurge/ax/master/screenshots/azure.png"/>
</a> 
</p>

<p align="center">
<a href="https://aws.com" target="_blank"> 
<img src="https://raw.githubusercontent.com/attacksurge/ax/master/screenshots/aws.png"/>
</a> 
</p>

<p align="center">
<a href="https://console.hetzner.cloud" target="_blank">
<img src="https://raw.githubusercontent.com/attacksurge/ax/master/screenshots/hetzner.png"/>
</a>
</p>

<p align="center">
<a href="https://cloud.google.com/free/docs/free-cloud-features" target="_blank">
<img src="https://raw.githubusercontent.com/attacksurge/ax/master/screenshots/gcp.png"/>
</a>
</p>

<p align="center">
<a href="https://www.scaleway.com/en/scaleway-vs-digitalocean/" target="_blank">
<img src="https://raw.githubusercontent.com/attacksurge/ax/master/screenshots/scaleway.png"/>
</a>
</p>

<p align="center">
<a href="https://community.exoscale.com/platform/quick-start/" target="_blank">
<img src="https://raw.githubusercontent.com/attacksurge/ax/Exoscale/screenshots/exoscale.png"/>
</a>
</p>

# Installation
The machine you install Ax on is called the [Ax Controller](https://ax-framework.gitbook.io/wiki/overview/ax-controller). The Controller manages all aspects of Ax, including account setup, building your Packer image, spinning up and SSHing into instances, creating new images from existing instances, deleting instances and images, managing distributed scanning, and much more! <br> <br>
During the initial installation, running [`ax configure`](https://github.com/attacksurge/ax/blob/master/interact/axiom-configure) will trigger [`ax account-setup`](https://github.com/attacksurge/ax/blob/master/interact/axiom-account-setup), which in turn calls [`ax account`](https://github.com/attacksurge/ax/blob/master/interact/axiom-account) along with the respective cloud provider's [`account-helper`](https://github.com/attacksurge/ax/tree/master/interact/account-helpers) script. Once this setup is complete, [`ax build`](https://github.com/attacksurge/ax/blob/master/interact/axiom-build) is executed to create your [Packer](https://www.packer.io/) image. After the image is successfully built, you can deploy fleets of servers using [`ax fleet`](https://github.com/attacksurge/ax/blob/master/interact/axiom-fleet) and distribute scans with [`ax scan`](https://github.com/attacksurge/ax/blob/master/interact/axiom-scan)!


## Docker

This will create a docker container, initiate the install and setup flow, then drop you out of the docker container. Once the Packer image is successfully created with [`ax build`](https://github.com/attacksurge/ax/blob/master/interact/axiom-build), you will have to re-exec into your docker container `docker exec -it $container_id zsh`. 
```
docker exec -it $(docker run -d -it --platform linux/amd64 ubuntu:latest) sh -c "apt update && apt install git -y && git clone https://github.com/attacksurge/ax/ ~/.axiom/ && cd && .axiom/interact/axiom-configure --run"
```

## Easy Install

You should use an OS that supports our [easy install](https://ax-framework.gitbook.io/wiki/overview/installation-guide#operating-systems-supported). <br>
For Linux systems you will also need to install the newest versions of all packages beforehand `sudo apt dist-upgrade`. <br>
```
bash <(curl -s https://raw.githubusercontent.com/attacksurge/ax/master/interact/axiom-configure) --run
```

If you have any problems with this installer, or if using an unsupported OS please refer to [Installation](https://ax-framework.gitbook.io/wiki/overview/installation-guide#operating-systems-supported).


## Operating Systems Supported
| OS         | Supported | Easy Install  | Tested        | 
|------------|-----------|---------------|---------------|
| Ubuntu     |    Yes    | Yes           | Ubuntu 22.04  |
| Kali       |    Yes    | Yes           | Kali 2024.2   |
| Debian     |    Yes    | Yes           | Debian 12     |
| Windows    |    Yes    | Yes           | WSL w/ Ubuntu |
| MacOS      |    Yes    | Yes           | macOS 14      |
| Arch Linux |    Yes    | No            | Yes           |

<br>

> __Bash:__ Ax is predominantly written in Bash! This makes it easy to contribute to, and it was chosen because [early versions](https://github.com/pry0cc/axiom) were rapidly prototyped in this language. For a detailed step-by-step walk-though of how ax scan works under the hood, its highly recommended to read the comments in the [source code](https://github.com/attacksurge/ax/blob/master/interact/axiom-scan)! 

<br>
<p align="center">
<a href="https://ax-framework.gitbook.io/wiki" target="_blank"> 
<img src="https://raw.githubusercontent.com/attacksurge/ax/master/screenshots/read-the-docs.png"/>
</a> 
</p>
