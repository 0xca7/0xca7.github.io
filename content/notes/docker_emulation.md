---
title: "Firmware Emulation with Docker"
date: 2022-11-14T19:24:18+01:00
draft: false
---

# Resources

My main resources for this post is the talk here: 

https://www.youtube.com/watch?v=ALn0hUxNszI&t=1288s

Credit to the Author.

I just took what he's doing and made it work on my machine, instead of MIPS I'm running ARM though. I expand upon the examples in the talk by adding some stuff of my own.

---

## Create a Dockerfile

MIPS from the talk in [Resources]:

```
FROM multiarch/debian-debootstrap:mips-buster-slim as qemu
FROM scratch
ADD ./firmware.tar.gz /
COPY --from=qemu /usr/bin/qemu-mips-static /usr/bin
CMD ["/usr/bin/qemu-mips-static", "bin/busybox"]
ENV ARCH=mips
```

ARM from my setup:

```
FROM multiarch/debian-debootstrap:armel-buster-slim as qemu
FROM scratch
ADD ./firmware.tar.gz /
COPY --from=qemu /usr/bin/qemu-arm-static /usr/bin
CMD ["/usr/bin/qemu-arm-static", "bin/busybox"]
ENV ARCH=arm
```

## Build the Container

Use the command:

```
docker build --rm -t [NAME] -f dockerfile .

# example
docker build --rm -t ARMcontainer -f dockerfile .
```

## Run the Container

Running the container is straight forward, however, I needed to load shared libaries as shown below.

```
docker run -it --rm [NAME]:latest [EXECUTABLE]

# example
docker run -it --rm router:latest sh

# in my case for the target firmware
docker run -it --rm armdocker:latest lib/ld-linux.so.3 --library-path lib/ userdisk/ControlCenter
```

## Manually Loading Shared Libraries

```
docker run -it --rm armdocker:latest lib/ld-linux.so.2 --library-path lib/ bin/busybox
docker run -it --rm armdocker:latest lib/ld-linux.so.2 --library-path lib/ etc/init.d/rcS
```

## Emulation of a Firmware Image

1. get the firmware
2. extract the filesystem
3. go to the file system root directory and do `tar cvf firmware.tar.gz .`
4. now copy `firmware.tar.gz` to the directory with the dockerfile 
5. build the container
6. run the container with the above commands

you should now be running an emulation of the firmware inside a docker container.
