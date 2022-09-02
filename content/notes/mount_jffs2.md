---
title: "Mount JFFS2 Filesystems"
date: 2022-08-31T19:09:03+02:00
draft: false
---

When reversing firmware, you often just get a blob of data from the vendor website. Usually, you look at it in a hex editor and/or run binwalk on it to identify what the blob contains. I often run into the JFFS2 filesystem (https://en.wikipedia.org/wiki/JFFS2).

Running `binwalk -e` on the firmware to extract the components will leave you with a `JFFS2` file which is not further extracted. The script below can be used on this file to mount it so you can get at the data contained in the filesystem.

Create a fake flash and mount the file system. Create a directory /mnt/disk first, this is where the jffs file, passed as a parameter will be mounted.

Assume you save the script as mount_jffs2.sh the usage is: 

```bash
# run as sudo
./mount_jffs2.sh [ path to image ]
```

```bash
#!/bin/bash

# change this if needed
TOTAL_RAM_SIZE=32768
ERASE_SIZE=256

# just the usage prompt
print_usage() {
    echo "usage ./mount_jffs2.sh [ path to image ]"
    echo "RUN THIS WITH SUDO / AS ROOT"
}

echo "[+] this script creates a fake flash drive"
echo "    and mounts a JFFS2 image to it."

# check if arg was supplied
if [ "$#" -ne 1 ]; then
    print_usage
    exit 1
fi

# check if root perms
if [ "$EUID" -ne 0 ]; then 
    print_usage
    exit 1
fi

echo "[+] modprobe mtdram and mtdblock"

# mtdram - simulates NOR flash in RAM
# mtdblock - presents flash memory as a block device you can use to 
# format and mount as a filesystem

modprobe mtdram total_size=$TOTAL_RAM_SIZE erase_size=$ERASE_SIZE
modprobe mtdblock

echo "[+] created /mnt/disk to mount to"
mkdir -p /mnt/disk

echo "[+] using dd to write image to /dev/mtdblock0"
dd if=$1 of=/dev/mtdblock0

echo "[+] mounting image to /mnt/disk"
mount -t jffs2 /dev/mtdblock0 /mnt/disk

echo "[+] done, see /mnt/disk:"
ls -l /mnt/disk
```
