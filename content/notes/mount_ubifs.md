---
title: "Mounting UBIFS"
date: 2023-02-25T20:51:56+01:00
draft: false
---

Detailed Information: http://trac.gateworks.com/wiki/linux/ubi

simulate a NAND device
```
modprobe nandsim first_id_byte=0x2c second_id_byte=0xac third_id_byte=0x90 fourth_id_byte=0x15
```

check if the device is set up
```
cat /proc/mtd
```

clean the device
```
flash_erase /dev/mtd0 0 0
```

format and flash

```
ubiformat /dev/mtd0 -f image.ubi -O 2048
```

attach device

```
modprobe ubi 
ubiattach -p /dev/mtd0 -O 2048
```

and now mount the device - mind you have to replace the `X` with `0,1,2...`

```
mount -t ubifs /dev/ubi0_X /mnt/ubifs
```
