---
title: "Latrodectus"
date: 2024-05-11T13:45:19+02:00
draft: false
---

Sample: `SHA256 805b59e48af90504024f70124d850870a69b822b8e34d1ee551353c42a338bf7`

## API Hashing

The malware uses API hashing to hide imported API functions. The hash function
used is CRC32:

```c
/* address: 0x180006aa4 */
uint64_t uc_crc32(int64_t a_name, int32_t a_namelen)
{
    if (data_180011318 == 0)
    {
        for (uint32_t i = 0; i < 0x100; i = (i + 1))
        {
            uint32_t i_2 = i;
            for (int32_t j = 8; j > 0; j = (j - 1))
            {
                if ((i_2 & 1) == 0)
                {
                    i_2 = (i_2 >> 1);
                }
                else
                {
                    i_2 = ((i_2 >> 1) ^ 0xedb88320);
                }
            }
            *(uint32_t*)(&data_180010f18 + (((uint64_t)i) << 2)) = i_2;
        }
        data_180011318 = 1;
    }
    int32_t var_10 = 0xffffffff;
    for (int32_t i_1 = 0; i_1 < a_namelen; i_1 = (i_1 + 1))
    {
        var_10 = ((var_10 >> 8) ^ *(uint32_t*)(&data_180010f18 + (((uint64_t)(*(uint8_t*)(a_name + ((uint64_t)i_1)) ^ var_10)) << 2)));
    }
    return ((uint64_t)!(var_10));
}
```

Functions are resolved using the hash value, the DLL base address to load the
function from and an address to store the resulting function pointer. Below is
an example for `VirtualAlloc` from `kernel32.dll`:

```c
/* address: 0x18000949a */
/* hash */
int32_t var_878 = 0x9ce0d4a;
/* dll base address to load from */
void* var_870 = &g_KERNEL32DLL_BASE;
/* pointer to the location the function address will be stored */
int64_t* v_func_addr = &g_VirtualAlloc;
```

The `(hash, dll_base, pointer)` triple is built on the stack, one for each
function to import, a loop does the importing via API Hashing 
(example: `0x18000a2f3`).

API Hashing is easily defeated using hashdb (`https://github.com/OALabs/hashdb`)
for the disassembler of choice. Through this, the parts of the malware used
for C2 communication are identified. For example `InternetOpenW`:

```c
/* address: 180004c70 */
int64_t uc_connect(int64_t arg1, int64_t a_SERVERNAME, int16_t arg3)
{
    int32_t r9;
    arg_20 = r9;
    int64_t var_10 = 0;
    int32_t var_30;
    int32_t var_28;
    int64_t var_20;
    int64_t v_inethandle = g_InternetOpenW(arg1, 0, 0, 0, 0, var_30, 
        var_28, var_20, 0, var_10);
    if (v_inethandle != 0)
    {
        var_20 = 1;
        var_28 = 0;
        var_30 = 3;
        var_10 = g_InternetConnectA(v_inethandle, a_SERVERNAME, 
            ((uint64_t)arg3), 0, 0, 3, 0, 1, v_inethandle);
    }
    return var_10;
}
```

Backtracking from `InternetConnectA` eventually leads to the following function:

```c
/* address: 180006988 */
int64_t sub_180006988()
{
    data_1800109b4 = 0;
    g_URL_STORAGE = uc_allocate(0x18);
    void* a_str;
    void aout;
    if (uc_?_decrypt(&data_180010250, &aout) == 0)
    {
        a_str = &aout;
    }
    else
    {
        a_str = &aout;
    }
    *(uint64_t*)(g_URL_STORAGE + (((uint64_t)data_1800109b4) << 3)) = uc_strdup(a_str, uc_strlen(a_str));
    uint8_t* rax_4;
    rax_4 = data_1800109b4;
    rax_4 = (rax_4 + 1);
    data_1800109b4 = rax_4;
    void* a_str_1;
    if (uc_?_decrypt(&data_180010278, &aout) == 0)
    {
        a_str_1 = &aout;
    }
    else
    {
        a_str_1 = &aout;
    }
    *(uint64_t*)(g_URL_STORAGE + (((uint64_t)data_1800109b4) << 3)) = uc_strdup(a_str_1, uc_strlen(a_str_1));
    uint8_t* rax_8;
    rax_8 = data_1800109b4;
    rax_8 = (rax_8 + 1);
    data_1800109b4 = rax_8;
    *(uint64_t*)(g_URL_STORAGE + (((uint64_t)data_1800109b4) << 3)) = 0;
    return 1;
}
```

Here, an allocation for the C2 URLs is made, eventually, the URLs are decrypted.

## C2 URL

String decryption is done via the following function:

```c
/* address: 0x18000ae78 */
int64_t uc_?_decrypt(int32_t* ain, int64_t aout)
{
    // the first 32-bits of the input
    int32_t ain[0] = *(uint32_t*)ain;
    // xor'd with the next 32-bits of the input
    int16_t v_xor = (ain[0] ^ ain[1]);
    int16_t i = 0;
    while (((uint32_t)i) < ((uint32_t)v_xor))
    {
        uint64_t v_cur0;  // byte 6 onwards
        v_cur0 = *(uint8_t*)(((char*)ain + 6) + ((uint64_t)i));
        char v_cur_00 = v_cur0;
        uint64_t v_cur1;
        v_cur1 = *(uint8_t*)(((char*)ain + 6) + ((uint64_t)i));
        char var_17_2 = ((v_cur1 + v_cur_00) + 0xa);
        ain[0] = uc_add_one(ain[0]);
        *(uint8_t*)(aout + ((uint64_t)i)) = ((*(uint8_t*)(aout + ((uint64_t)i)) + v_cur_00) + 0xa);
        *(uint8_t*)(aout + ((uint64_t)i)) = (v_cur_00 ^ ain[0]);
        i = (i + 1);
    }
    return aout;
}
```

Translated to python this becomes:

```python3

"""
decrypts a string and returns a 8-bit and 16-bit string as these are mixed
in the malware
"""
def decrypt(encrypted):

    out = []
    a0 = int.from_bytes(encrypted[0:4], "little")
    a1 = int.from_bytes(encrypted[4:8], "little")
    length = (a0 ^ a1) & 0xffff

    key = a0
    for i in range(0, length):
        val = encrypted[6 + i]
        key = key + 1
        out.append((val ^ key) & 0xff)

    # interpret as wide string
    wide = "".join([chr(out[i]) for i in range(0,len(out),2)])
    return ("".join([chr(byte) for byte in out]), wide)
```

Note that the malware contains wide strings and 8-bit strings.

As an example for an encrypted string, take a look at these two.

```
18000f7d0  data_18000f7d0:
18000f7d0  7e d0 dd ad 71 d0 59 f7 e9 ed e2 e9 ec d9 e0 fa  ~...q.Y.........
18000f7e0  e6 ff fb b1 8d 00 00 00                          ........
--- SNIP ---
18000f7f0  data_18000f7f0:
18000f7f0  7e d0 dd ad 76 d0 5d f0 e8 e6 a1 be a5 86 00 00  ~...v.].........
```

Each encrypted string starts with a sequence of 4 bytes which is the same for
all encrypted strings. This sequence is unique for each sample analyzed for this
report. Here, the sequence is `0x7e 0xd0 0xdd 0xad`. Further, `0x00` delimits
each string.

As such, searching for encrypted strings can be automated, as well as the decryption
and search for URLs via the following code. In addition to the sample mentioned
at the start of this report, `SHA256 6091f2589fef42e0ab3d7975806cd8a0da012b519637c03b73f702f7586b21ef`
was also analyzed. Here, the 4-byte sequence prepended to encrypted strings differs
and is given in `STRING_ANCHOR1` in the script below. For the sample `SHA256 805b59e48af90504024f70124d850870a69b822b8e34d1ee551353c42a338bf7`,
the sequence is stored in `STRING_ANCHOR0`.

```python
"""
config extraction for sample 
SHA256: 805b59e48af90504024f70124d850870a69b822b8e34d1ee551353c42a338bf7

the url of the C2 server is encrypted using some custom encryption algorithm
the malware resolves APIs by PEB walk and API hashing with CRC32 (0xEDB88320)

an encrypted string starts with "0x7e 0xd0 0xdd 0xad" and ends with "0x00"
we'll call the first 4 bytes the STRING_ANCHOR
"""

import re

STRING_ANCHOR0 = b"~\xd0\xdd\xad"
STRING_ANCHOR1 = b"@\x9db3"

REGEXP_URL = "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"

"""
decrypt a string
"""
def decrypt(encrypted):

    out = []
    a0 = int.from_bytes(encrypted[0:4], "little")
    a1 = int.from_bytes(encrypted[4:8], "little")
    length = (a0 ^ a1) & 0xffff

    key = a0
    for i in range(0, length):

        # in case we caught something that isn't a valid encrypted string
        if len(encrypted) <= 6+i:
            return (None, None)

        val = encrypted[6 + i]
        key = key + 1
        out.append((val ^ key) & 0xff)

    # interpret as wide string
    wide = "".join([chr(out[i]) for i in range(0,len(out),2)])
    ascii = "".join([chr(byte) for byte in out])
    return (ascii, wide)


"""
once a string anchor is found, collect the encrypted string
"""
def extract_string(data) -> bytearray:
    
    i = 0
    bytes = bytearray()
    while data[i].to_bytes() != b"\x00":
        bytes += bytearray(data[i].to_bytes())
        i += 1
    bytes += b"\x00"
    
    return bytes


"""
find string anchors and collecte encrypted strings
"""
def find_encrypted(data, string_anchor) -> list:
    
    encrypted = []
    for i in range(0, len(data), len(string_anchor)):
        if data[i:i+len(string_anchor)] == string_anchor:
            bytes = extract_string(data[i:])
            encrypted.append(bytes)

    return encrypted 

def extract(path, string_anchor):

    encrypted = None

    with open(path, "rb") as fp:
        data = fp.read()
        encrypted = find_encrypted(data, string_anchor)

    print(">> found {} encrypted strings, decrypting".format(len(encrypted)))
    decrypted = map(decrypt, encrypted)

    # search for URLS
    for (ascii, wide) in decrypted:
        if ascii:
            x = re.match(REGEXP_URL, ascii)
            if x:
                url = x[0].replace('.', '[.]', 1)
                print("[URL] {}".format(url))
        if wide:
            x = re.match(REGEXP_URL, wide)
            if x:

                url = x[0].replace('.', '[.]', 1)
                print("[URL] {}".format(url))

def main():

    path = "../sample/805b59e48af90504024f70124d850870a69b822b8e34d1ee551353c42a338bf7.exe"
    print(">> extracting path: {}".format(path))
    extract(path, STRING_ANCHOR0)

    path = "../sample/6091f2589fef42e0ab3d7975806cd8a0da012b519637c03b73f702f7586b21ef.exe"
    print(">> extracting path: {}".format(path))
    extract(path, STRING_ANCHOR1)

if __name__ == '__main__':
    main()
```

The anchor can also be found automatically:

```
"""
automatically find the anchor for an unknown sample.
"""
def find_anchor(path):

    data = []
    with open(path, "rb") as fp:
        data = fp.read()

    seq = list()

    for i in range(0, len(data), 4):
        if b"\x00" not in bytearray(data[i:i+4]):
            seq.append(data[i:i+4])

    seq = sorted(seq, key=seq.count, reverse=True)
    return seq

path = "../sample/465f931e8a44b7f8dff8435255240b88f88f11e23bc73741b21c20be8673b6b7.exe"
print(">> extracting path: {}".format(path))
anchor = find_anchor(path)
```

Adding this to the config extraction above gives the following script:

```python
"""
config extraction for sample 
SHA256: 805b59e48af90504024f70124d850870a69b822b8e34d1ee551353c42a338bf7

the url of the C2 server is encrypted using some custom encryption algorithm
the malware resolves APIs by PEB walk and API hashing with CRC32 (0xEDB88320)

an encrypted string starts with "0x7e 0xd0 0xdd 0xad" and ends with "0x00"
we'll call the first 4 bytes the STRING_ANCHOR
"""

import re

STRING_ANCHOR0 = b"~\xd0\xdd\xad"
STRING_ANCHOR1 = b"@\x9db3"

REGEXP_URL = "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"

"""
automatically find the anchor for an unknown sample.
"""
def find_anchor(path):

    data = []
    with open(path, "rb") as fp:
        data = fp.read()

    seq = list()

    for i in range(0, len(data), 4):
        if b"\x00" not in bytearray(data[i:i+4]):
            seq.append(data[i:i+4])

    seq = sorted(seq, key=seq.count, reverse=True)
    return seq

"""
decrypt a string
"""
def decrypt(encrypted):

    out = []
    a0 = int.from_bytes(encrypted[0:4], "little")
    a1 = int.from_bytes(encrypted[4:8], "little")
    length = (a0 ^ a1) & 0xffff

    key = a0
    for i in range(0, length):

        # in case we caught something that isn't a valid encrypted string
        if len(encrypted) <= 6+i:
            return (None, None)

        val = encrypted[6 + i]
        key = key + 1
        out.append((val ^ key) & 0xff)

    # interpret as wide string
    wide = "".join([chr(out[i]) for i in range(0,len(out),2)])
    ascii = "".join([chr(byte) for byte in out])
    return (ascii, wide)


"""
once a string anchor is found, collect the encrypted string
"""
def extract_string(data) -> bytearray:
    
    i = 0
    bytes = bytearray()
    while data[i].to_bytes() != b"\x00":
        bytes += bytearray(data[i].to_bytes())
        i += 1
    bytes += b"\x00"
    
    return bytes


"""
find string anchors and collecte encrypted strings
"""
def find_encrypted(data, string_anchor) -> list:
    
    encrypted = []
    for i in range(0, len(data), len(string_anchor)):
        if data[i:i+len(string_anchor)] == string_anchor:
            bytes = extract_string(data[i:])
            encrypted.append(bytes)

    return encrypted 

def extract(path, string_anchor):

    encrypted = None

    with open(path, "rb") as fp:
        data = fp.read()
        encrypted = find_encrypted(data, string_anchor)

    print(">> found {} encrypted strings, decrypting".format(len(encrypted)))
    decrypted = map(decrypt, encrypted)

    # search for URLS
    for (ascii, wide) in decrypted:
        if ascii:
            x = re.match(REGEXP_URL, ascii)
            if x:
                url = x[0].replace('.', '[.]', 1)
                print("[URL] {}".format(url))
        if wide:
            x = re.match(REGEXP_URL, wide)
            if x:

                url = x[0].replace('.', '[.]', 1)
                print("[URL] {}".format(url))

def main():

    path = "../sample/805b59e48af90504024f70124d850870a69b822b8e34d1ee551353c42a338bf7.exe"
    print(">> extracting path: {}".format(path))
    extract(path, STRING_ANCHOR0)

    path = "../sample/6091f2589fef42e0ab3d7975806cd8a0da012b519637c03b73f702f7586b21ef.exe"
    print(">> extracting path: {}".format(path))
    extract(path, STRING_ANCHOR1)

    path = "../sample/465f931e8a44b7f8dff8435255240b88f88f11e23bc73741b21c20be8673b6b7.exe"
    print(">> extracting path: {}".format(path))
    anchor = find_anchor(path)
    print(">> found anchor: {}".format(anchor[0]))
    extract(path, anchor[0])

if __name__ == '__main__':
    main()

```

This yields:

```
>> extracting path: ../sample/805b59e48af90504024f70124d850870a69b822b8e34d1ee551353c42a338bf7.exe
>> found 127 encrypted strings, decrypting
[URL] https://titnovacrion[.]top/live/
[URL] https://skinnyjeanso[.]com/live/
>> extracting path: ../sample/6091f2589fef42e0ab3d7975806cd8a0da012b519637c03b73f702f7586b21ef.exe
>> found 127 encrypted strings, decrypting
[URL] https://titnovacrion[.]top/live/
[URL] https://skinnyjeanso[.]com/live/
>> extracting path: ../sample/465f931e8a44b7f8dff8435255240b88f88f11e23bc73741b21c20be8673b6b7.exe
>> found anchor: b'\x03a\x90\x8a'
>> found 127 encrypted strings, decrypting
[URL] https://winarkamaps[.]com/live/
[URL] https://stratimasesstr[.]com/live/
```

## Summary

The report provides string decryption, automatic detection of encrypted strings and 
the automatic extraction of the C2 URLs for the three analyzed samples.


```
805b59e48af90504024f70124d850870a69b822b8e34d1ee551353c42a338bf7
6091f2589fef42e0ab3d7975806cd8a0da012b519637c03b73f702f7586b21ef
465f931e8a44b7f8dff8435255240b88f88f11e23bc73741b21c20be8673b6b7
```

0xca7



