---
title: "Docker"
date: 2022-08-31T17:55:52+02:00
draft: false
---

# Docker

notes about how to do things with docker for reference.

# Installation 

Best to get the version directly from docker.com, see:

`https://docs.docker.com/engine/install/debian/`

or

`https://docs.docker.com/engine/install/ubuntu/`

# Images

You can get official images via docker directly. See `https://hub.docker.com/` - this shows the commands to pull images.

Example:

```
docker pull debian
```

# Containers

Creating a container from the image can be done as follows:

Create a container `debian_test` based on the `debian` image with full host network access, launch it and attach to it.

```
docker run -it --net=host --name=debian_test debian
```

If the container is off, you can do the following:

```
# start the container
docker start debian_test
# attach to it
docker container attach debian_test
# when you're done
docker stop debian_test
```

Show all containers, running and not running:

```
docker ps -a 
```

Create a container based on debian image, attach a shared storage and host network to container. Syntax is `-v HOST_SOURCE_DIR:GUEST_DESTINATION_DIR 

```
docker run -it --net=host --name=debian_test -v ~/docker/container_data:/data debian
```

# Network Interfaces

Create a container `deb0` with shared storage and attach it to a bridge network. Create another container `deb1`.

```
docker run -it -h deb0 --net=bridge --name=deb0 -v ~/docker/container_data:/data debian
docker run -it -h deb1 --net=bridge --name=deb1 -v ~/docker/container_data:/data debian
```

Get the IP address of a container
```
docker inspect <container_id> | grep IPAddress
```

Multiple Network Interfaces:

see: https://stackoverflow.com/questions/34110416/start-container-with-multiple-network-interfaces

```
docker create --network=network1 --name container_name containerimage:latest
docker network connect network2 container_name
docker start container_name
docker network create --driver=bridge network1 --subnet=172.19.0.0/24
docker network create --driver=bridge network2 --subnet=172.19.1.0/24
```

# Image from Container

Show images

```
docker images -a 
```

Save container with a tag

```
docker commit [container name] [image name]
```

Save a container WITHOUT A TAG

```
docker commit [container name]
```

Container is saved with tag `none`

now you can tag it.

```
docker tag [container ID] name
```

# Save an Image / Container

```
docker save [image ]> [image].tar
docker save [image]:latest | gzip > [name].tar.gz
```

---
