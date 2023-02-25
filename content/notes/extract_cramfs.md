---
title: "Extract cramfs"
date: 2023-02-25T20:56:49+01:00
draft: false
---

check if LE or BE
```
file cramfs
```

if the file is big endian, make it little endian with this
```
cramfsswap cramfs cramfs_le
```

extract 
```
# if not converted via the command above, cramfs is little endian
sudo fsck.cramfs --extract=fs cramfs
# if converted via the command above, the file is renamed to "cramfs_le"
sudo fsck.cramfs --extract=fs cramfs_le
```

