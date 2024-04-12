# Installation
## Docker

This will create a docker container, initiate [`axiom-configure`](https://github.com/pry0cc/axiom/wiki/Filesystem-Utilities#axiom-configure) and [`axiom-build`](https://github.com/pry0cc/axiom/wiki/Filesystem-Utilities#axiom-build) and then drop you out of the docker container. Once the [Packer](https://www.packer.io/) image is successfully created, you will likely need to re-exec into your docker container via `docker exec -it $container_id zsh`.
```
docker exec -it $(docker run -d -it --platform linux/amd64 ubuntu:20.04) sh -c "apt update && apt install git -y && git clone https://github.com/attacksurge/ax/ ~/.axiom/ && cd && .axiom/interact/axiom-configure --setup"
```

## Easy Install

You should use an OS that supports our [easy install](https://github.com/pry0cc/axiom#operating-systems-supported). <br>
For Linux systems you will also need to install the newest versions of all packages beforehand `sudo apt dist-upgrade`. <br>
```
bash <(curl -s https://raw.githubusercontent.com/attacksurge/ax/master/interact/axiom-configure)
```

If you have any problems with this installer, or if using an unsupported OS please refer to [Installation](https://github.com/pry0cc/axiom/wiki/0-Installation).


## Operating Systems Supported
| OS         | Supported | Easy Install  | Tested        | 
|------------|-----------|---------------|---------------|
| Ubuntu     |    Yes    | Yes           | Ubuntu 20.04  |
| Kali       |    Yes    | Yes           | Kali 2021.3   |
| Debian     |    Yes    | Yes           | Debian 10     |
| Windows    |    Yes    | Yes           | WSL w/ Ubuntu |
| MacOS      |    Yes    | Yes           | MacOS 11.6    |
| Arch Linux |    Yes    | No            | Yes           |


