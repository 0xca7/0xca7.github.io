---
title: "Wineloader"
date: 2024-03-16T10:27:33Z
draft: false 
---

SHA256: `72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4`

Resources:
[1] https://www.zscaler.com/blogs/security-research/european-diplomats-targeted-spikedwine-wineloader

# Summary

The article in the resources above contains all the important information about the sample.

Goals:

- find the C2 URL, just to have fun.

- These analysis notes add to the zscaler report [1] by showing how to reach a subset of the presented conclusions and supply code snippets to help with analysis. Specifically, the means to statically decrypt the main payload of the sample are given, as well as a means for decrypting strings and the C2 URL used by the malware.

- This writeup supplies code and deeper explanations which might be useful for beginners, but not relevant for reporting. 

# Static Analysis

All static analysis was done using IDA Free 8.3 and Binary Ninja 4.0. The entropy graph shows that a large area of the executable seems to be encrypted or at least compressed. In this case, it is RC4 encryption.

![image.png](/static/819048f2-9864-4011-a792-259cde85d580.png)

As stated in [1], the exported function which is used as an entrypoint by the calling executable is `_set_se_translator`. The assembly code is shown below.

![image.png](/static/feb9ab8a-88e0-4ed6-962a-9913fee7e68d.png)

The lines which are interesting here are:

```
lea     rcx, word_18000649E
mov     rdx, 8028h
```

The address denoted as `word_18000649E` is the start of the encrypted main module, which a length of `0x8028` bytes.
Both of these values are parameters for the call to `sub_1800061CE`, which in turn calls `sub_180005B3E`. Inside of `sub_180005B3E` is the RC4 initialization:

```c
  v7 = 0;
  *i = 0;
  while ( (v7 & 1) == 0 )
  {
    *(_BYTE *)(a_RC4_state + (unsigned __int8)*i) = *i;  // <-- [M0]
    a4 *= 0x6FC9A775;
    if ( (unsigned __int8)*i == 255 )
    {
      v7 = 1;
      a4 *= 0x3A6A1BD5;
    }
    ++*i; // <-- [M1]
  }
```

There are some unnecessary parts in this loop, which is probably for "obfuscation" purposes. In essence, all this does is:

```c
for(i = 0; i < 256; i++)
{
    state[i] = i; // M0, M1
}
```

The next part of the function `sub_180005B3E` is this (I already renamed to key to `g_KEY`:

```c
  for ( *i = 0; ; ++*i )
  {
    result = v8 & 1;
    if ( (v8 & 1) != 0 )
      break;
    *j += *((_BYTE *)&g_KEY + (unsigned __int8)*i % 256) + *(_BYTE *)(a_RC4_state + (unsigned __int8)*i); // <-- [M0]
    ((void (__fastcall *)(__int64, __int64, __int64, __int64, int))loc_1800059FE)( // <-- [M1]
      (unsigned __int8)*i + a_RC4_state,
      (unsigned __int8)*j + a_RC4_state,
      0x3B908B94i64,
      0xFA51i64,
      0x3CD5);
    v6 = (v6 % -1543287202) & 0x5CCA8034;
    if ( (unsigned __int8)*i == 255 )
    {
      v8 = 1;
      v5 *= -1177247145;
    }
  }
```

Again, there is some "obfuscation" in here, but in essence, this happens:

```c
j = j + state[i] + key[i mod keylength] mod 256
swap(state[i], state[j])
```

The first line of the above code corresponds to `M[0]`. The call at `M[1]` is a little trickier. Here, IDA makes a mistake, the get the decompiler to display this correctly, do the following:

1. follow `loc_1800059FE` in the assembly view.

```
.text:00000001800059FE loc_1800059FE:                          ; CODE XREF: sub_180005B3E+19C↓p // <-- YOU ARE HERE.
.text:00000001800059FE                                         ; sub_180005DDE+AA↓p
.text:00000001800059FE                 sub     rsp, 28h
.text:0000000180005A02                 mov     ax, [rsp+50h]
.text:0000000180005A07
.text:0000000180005A07 loc_180005A07:                          ; DATA XREF: .pdata:00000001800172B8↓o
.text:0000000180005A07                 mov     [rsp+26h], r9w
.text:0000000180005A07 ; ---------------------------------------------------------------------------
.text:0000000180005A0D                 db 44h, 89h, 44h  // <-- [M0]
```

2. put the cursor at `M[0]` as shown in the assembly snippet above and press `c` to create code here
3. put the cursor at `loc_1800059FE` and create a function by pressing `p`
4. go back to the decompiler view, function `sub_180005B3E` and press `F5`

You now have a function call to `sub_1800059FE` instead of a call to `((void (__fastcall *)(__int64, __int64, __int64, __int64, int))loc_1800059FE)(...`, which if followed, is just a simple swap function:

```c
__int64 __fastcall sub_1800059FE(char *a1, char *a2)
{
  char v3; // [rsp+Fh] [rbp-19h]

  v3 = *a1;
  *a1 = *a2;
  *a2 = v3;
  return 0i64;
}
```

Thus, the function `sub_1800059FE` corresponds to `https://en.wikipedia.org/wiki/RC4#Key-scheduling_algorithm_(KSA)`. We also know where the key is located.

With this, we everything necessary for decryption:

1. we know RC4 is the algorithm
2. we have the data and data length which is to be decrypted
3. we have the key

The following Python3 code will read the sample, decrypt the encrypted range of bytes and save the result to a new file `decrypted.bin` which can be used for further analysis.


```python
from Crypto.Cipher import ARC4

FILE = "72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4.exe"

# this is the raw file offset to the encryption key
KEY_OFFSET = 0x4a9e
# the encryption key length in bytes
KEYBYTES = 256
# the raw file offset to the encrypted payload
ENCRYPTED_OFFSET = 0x589e
# the number of bytes to decrypt
ENCRYPTED_BYTES = 0x8028

# read the original sample
filebytes = None
with open(FILE, "rb") as fp:
    filebytes = fp.read()

# extract key and ciphertext
key = filebytes[KEY_OFFSET:KEY_OFFSET+KEYBYTES]
data = filebytes[ENCRYPTED_OFFSET:ENCRYPTED_OFFSET+ENCRYPTED_BYTES]

# perform decryption
cipher = ARC4.new(key)
decrypted = cipher.encrypt(data)

print("decrypted len: {}".format(len(decrypted)))

# replace the encrypted bytes of the file with the decrypted result
file = filebytes[:ENCRYPTED_OFFSET];
file += decrypted
file += filebytes[ENCRYPTED_OFFSET+ENCRYPTED_BYTES:]

# write everything to a new file for analyis
with open("decrypted.bin", "wb") as fp:
    fp.write(file)
```

    decrypted len: 32808


The raw file offsets can be extracted from as shown below:

![image.png](/static/d7855854-bc3f-4737-87b9-bd1ddee759a7.png)

The cursor must be set to the location to determine the offset of, IDA will always show the raw file offset.

Having decrypted the payload, further analysis is possible in the decrypted sample.

Going back to the first screenshot of these analysis notes, the function `sub_18000CF2A` contains the decrypted main routine.

In this function, there are several calls to `sub_180007096` (called 214 times in total in the sample). The parameter to the call are always byte arrays, either passed on the stack or stored in a global variable.

```
.text:000000018000CF58                 mov     qword ptr [rdi-8], 0Ch
.text:000000018000CF60                 mov     rax, 6FBA78ED00F7D404h
.text:000000018000CF6A                 mov     [rdi], rax
.text:000000018000CF6D                 mov     dword ptr [rdi+8], 0FCF1BF11h
.text:000000018000CF74                 mov     r14d, 1
.text:000000018000CF7A                 mov     [rdi+0Ch], r14
.text:000000018000CF7E                 mov     edx, 0Ch
.text:000000018000CF83                 mov     rcx, rdi
.text:000000018000CF86                 call    sub_180007096  // <-- M[0] encrypted string on the stack


.text:000000018000CF8B                 xor     ebp, ebp
.text:000000018000CF8D                 mov     [rdi+0Ch], ebp
.text:000000018000CF90                 lea     rbx, [rsp+198h+v_data]
.text:000000018000CF95                 mov     qword ptr [rbx-8], 1Ah
.text:000000018000CF9D
.text:000000018000CF9D loc_18000CF9D:                          ; DATA XREF: .pdata:000000018001778C↓o
.text:000000018000CF9D                 movups  xmm6, cs:g_ENCRYPTED // <-- M[1] encrypted string is a global
.text:000000018000CFA4
.text:000000018000CFA4 loc_18000CFA4:                          ; DATA XREF: .pdata:0000000180017798↓o
.text:000000018000CFA4                 movups  xmmword ptr [rbx], xmm6
.text:000000018000CFA7                 movups  xmm7, cs:g_ENCRYPTED+0Ah
.text:000000018000CFAE                 movups  xmmword ptr [rbx+0Ah], xmm7
.text:000000018000CFB2                 mov     [rbx+1Ch], r14
.text:000000018000CFB6                 mov     edx, 1Ah
.text:000000018000CFBB                 mov     rcx, rbx
.text:000000018000CFBE                 call    sub_180007096
```

Upon closer examination, the function `sub_180007096` is RC4 again, with the first argument being an encrypted string and the second argument being the string length.

```c
__int64 __fastcall sub_180007096(__int64 a1, __int64 a2)
{
  char v4; // [rsp+2Eh] [rbp-12Ah] BYREF
  char v5; // [rsp+2Fh] [rbp-129h] BYREF
  char v_rc4_state; // [rsp+30h] [rbp-128h] BYREF
  unsigned __int8 v7; // [rsp+31h] [rbp-127h]

  uc_memset(&v_rc4_state, 0i64, 256i64);
  v5 = 0;
  v4 = 0;
  uc_RC4_init_dec(&v5, &v4, &v_rc4_state);
  if ( !a2 )
    JUMPOUT(0x180007124i64);
  return uc_RC4_decrypt_0(v7, 1i64, v7, v7);
}
```

The function renamed to `uc_RC4_init_dec` (`sub_18000D847`) is again the initialization of RC4 using the same key that was used to decrypt the main module:

```c
__int64 __fastcall sub_18000D847(unsigned __int8 *ai, unsigned __int8 *aj, __int64 a_rc4state)
{
  char v3; // al
  unsigned __int8 v4; // r10
  __int64 result; // rax
  unsigned __int8 v6; // r11
  unsigned __int8 v7; // bl
  __int64 v8; // r11
  __int64 v9; // rsi
  char v10; // bl

  *ai = 0;
  v3 = 0;
  v4 = 0;
  do
  {
    *(_BYTE *)(a_rc4state + v4) = v4;
    v4 = *ai + 1;
    if ( *ai == 0xFF )
      v3 = 1;
    *ai = v4;
  }
  while ( (v3 & 1) == 0 );
  LOBYTE(result) = 0;
  *aj = 0;
  *ai = 0;
  v6 = 0;
  do
  {
    v7 = *((_BYTE *)&g_KEY + v6) + *aj + *(_BYTE *)(a_rc4state + v6);
    *aj = v7;
    v8 = v7;
    v9 = *ai;
    v10 = *(_BYTE *)(a_rc4state + v9);
    *(_BYTE *)(a_rc4state + v9) = *(_BYTE *)(a_rc4state + v8);
    *(_BYTE *)(a_rc4state + v8) = v10;
    v6 = *ai + 1;
    result = (unsigned __int8)result;
    if ( *ai == 0xFF )
      result = 1i64;
    *ai = v6;
  }
  while ( (result & 1) == 0 );
  return result;
}
```

Thus, RC4 is used for string decryption, always with the same key for the main module. As stated above, there are two cases of how the call to the RC4 decryption function is made:

1. the parameters to the call, the encrypted string and it's length, are stored in a global variable
2. the parameters are passed via buffer on the stack.

This allows us to write Python3 code, which will handle the decryption by using either file offsets for global locations or the values assembled in stack buffers.


```python
"""
decrypt wineloader payload
"""
from Crypto.Cipher import ARC4
import struct

FILE = "code/decrypted.bin"
KEY_OFFSET = 0x58be
KEYBYTES = 256
ENCRYPTED_OFFSET = 0x6296
ENCRYPTED_BYTES = 0x1a

filebytes = None
with open(FILE, "rb") as fp:
    filebytes = fp.read()

# this can be done in case of a global variable
key = filebytes[KEY_OFFSET:KEY_OFFSET+KEYBYTES]
data = filebytes[ENCRYPTED_OFFSET:ENCRYPTED_OFFSET+ENCRYPTED_BYTES]

# here, we decrypt the library name
cipher = ARC4.new(key)
decrypted = cipher.encrypt(data)
s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("decrypted offset {:x}: {}".format(ENCRYPTED_OFFSET, s))

# this is the function that is being loaded from the lib
bytes = struct.pack('<Q', 0x6FBA78ED00F7D404)
bytes += struct.pack('<I', 0xFCF1BF11)
bytes += struct.pack('<Q', 0x1)

cipher = ARC4.new(key)
decrypted = cipher.encrypt(bytes)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("decrypted: {}".format(s))
```

    decrypted offset 6296: kernel32.dll
    decrypted: FreeConsole*`


In order to find the C2 URL, I just skimmed the file and selectively decrypted strings. By decrypting the string `kernel32.dll` right at the beginning and checking where it is used, I found this:
```c
struct _LIST_ENTRY *__fastcall sub_180007260(__int64 a1)
{
  struct _PEB_LDR_DATA *Ldr; // r8
  struct _LIST_ENTRY *Flink; // rdx
  struct _LIST_ENTRY *p_InMemoryOrderModuleList; // r8
  struct _LIST_ENTRY *result; // rax
  __int64 v5; // r10
  __int16 v6; // si
  __int16 v7; // r11
  __int16 v8; // bx
  __int16 v9; // di

  Ldr = NtCurrentPeb()->Ldr;
  Flink = Ldr->InMemoryOrderModuleList.Flink;
  p_InMemoryOrderModuleList = &Ldr->InMemoryOrderModuleList;
  result = 0i64;
  while ( 2 )
  {
    if ( Flink != p_InMemoryOrderModuleList )
    {
      v5 = 0i64;
      while ( 1 )
      {
        v6 = *(_WORD *)(a1 + v5);
        v7 = *(_WORD *)((char *)&Flink[5].Flink->Flink + v5);
        if ( !v6 )
          break;
        v8 = v6 + 32;
        if ( (unsigned __int16)(v6 - 65) >= 0x1Au )
          v8 = *(_WORD *)(a1 + v5);
        v9 = v7 + 32;
        if ( (unsigned __int16)(v7 - 65) >= 0x1Au )
          v9 = *(_WORD *)((char *)&Flink[5].Flink->Flink + v5);
        v5 += 2i64;
        if ( v8 != v9 )
          goto LABEL_12;
      }
      if ( v7 )
      {
LABEL_12:
        Flink = Flink->Flink;
        continue;
      }
      return Flink[2].Flink;
    }
    return result;
  }
}
```

A PEB walk is used get handles to libraries (see: https://www.youtube.com/watch?v=Tk3RWuqzvII). Thus, checking where the handles are used lead to `sub_18000D8FE`, which loads a specific library function.

As I knew that at some point, the C2 is contacted, the control flow allowed me to make assumptions regarding which strings to decrypt.
Below, you can see this process. As soon as I found `POST`, I knew I was in the right corner of the binary to look for the C2 URL. Eventually, after finding `wininet.dll` and `InternetConnectW` I got the URL.

```
sub_18000CF2A // main function
    sub_18000B3BB // eventually called by main, decrypts the string "POST"
        sub_18000A1A9 // string "POST" is passed to this
            sub_1800094D4 // decrypts the string "wininet.dll" and "InternetConnectW"
                InternetConnectW // second parameter is the URL to connect to.
    

```


```python
"""
decrypt wineloader payload
"""
from Crypto.Cipher import ARC4
import struct

FILE = "code/decrypted.bin"
KEY_OFFSET = 0x58be
KEYBYTES = 256
ENCRYPTED_OFFSET = 0x6296
ENCRYPTED_BYTES = 0x1a

filebytes = None
with open(FILE, "rb") as fp:
    filebytes = fp.read()

key = filebytes[KEY_OFFSET:KEY_OFFSET+KEYBYTES]
data = filebytes[ENCRYPTED_OFFSET:ENCRYPTED_OFFSET+ENCRYPTED_BYTES]

# here, we decrypt the library name
cipher = ARC4.new(key)
decrypted = cipher.encrypt(data)
s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("decrypted offset {:x}: {}".format(ENCRYPTED_OFFSET, s))

# this is the function that is being loaded from the lib
bytes = struct.pack('<Q', 0x6FBA78ED00F7D404)
bytes += struct.pack('<I', 0xFCF1BF11)
bytes += struct.pack('<Q', 0x1)

cipher = ARC4.new(key)
decrypted = cipher.encrypt(bytes)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("decrypted: {}".format(s))

# bookmark TAG1 -> HeapAlloc*
bytes = struct.pack('<Q', 0x73B87BEF15F3C30A)
bytes += struct.pack('<I', 0x0D31D)
bytes += struct.pack('<Q', 0x1)
cipher = ARC4.new(key)
decrypted = cipher.encrypt(bytes)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("TAG1: {}".format(s))

# bookmark TAG2
bytes = struct.pack('<Q', 0x79B778DC35E6C305)
bytes += struct.pack('<Q', 0x15904A99DCA00D79)
bytes += struct.pack('<Q', 0x1)
cipher = ARC4.new(key)
decrypted = cipher.encrypt(bytes)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("TAG2: {}".format(s))

# bookmark TAG3
bytes = struct.pack('<Q', 0x1C8017FD65DDA612)
bytes += struct.pack('<Q', 0xD37E)
cipher = ARC4.new(key)
decrypted = cipher.encrypt(bytes)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("TAG3: {}".format(s))

# bookmark TAG4
bytes = struct.pack('<Q', 0x79B165E815F3C30A)
bytes += struct.pack('<Q', 0x7E)
cipher = ARC4.new(key)
decrypted = cipher.encrypt(bytes)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("TAG4: {}".format(s))

# bookmark TAG5
bytes = struct.pack('<Q', 0x0F7CA11)
bytes += struct.pack('<I', 0x17DE)
bytes += struct.pack('<Q', 0x1)
cipher = ARC4.new(key)
decrypted = cipher.encrypt(bytes)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("TAG5: {}".format(s))

# bookmark TAG6
bytes = struct.pack('<Q', 0x6EB67EE201F3C90E)
bytes += struct.pack('<Q', 0x2BABEDA11F6EB67E)
bytes += struct.pack('<Q', 0x1)
cipher = ARC4.new(key)
decrypted = cipher.encrypt(bytes)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("TAG6: {}".format(s))

# bookmark TAG7
bytes = struct.pack('<Q', 0x68B179DC00E6C80B)
bytes += struct.pack('<Q', 0xE07C92F1A33168B1)
encrypted = bytearray([byte for byte in bytes if byte != '\x00'])
cipher = ARC4.new(key)
decrypted = cipher.encrypt(encrypted)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("TAG7: {}".format(s))

# bookmark TAG8
data = filebytes[0x5e36:0x5e36+0x18]
cipher = ARC4.new(key)
decrypted = cipher.encrypt(data)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("TAG8: {}".format(s))

# bookmark TAG9
data = filebytes[0x5c0e:0x5c0e+0x9e]
cipher = ARC4.new(key)
decrypted = cipher.encrypt(data)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("TAG8: {}".format(s))

# bookmark TAG9
data = filebytes[0x5cb6:0x5cb6+0x11]
cipher = ARC4.new(key)
decrypted = cipher.encrypt(data)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("TAG9: {}".format(s))

# bookmark TAG10
data = filebytes[0x5cd6:0x5cd6+0x22]
cipher = ARC4.new(key)
decrypted = cipher.encrypt(data)

s = "".join(["{}".format(chr(byte)) for byte in decrypted if byte >= 0x20 and byte <= 0x7f])
print("TAG10: {}".format(s))
```

    decrypted offset 6296: kernel32.dll
    decrypted: FreeConsole*`
    TAG1: HeapAlloc*`
    TAG2: GetProce4 a
    TAG3: POST+
    TAG4: HeapFree+
    TAG5: Slee*`
    TAG6: LoadLibrea
    TAG7: Internet_ri
    TAG8: wininet.dll
    TAG8: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.1) Gecko/20100101 Firefox/86.1
    TAG9: InternetConnectW
    TAG10: castechtools[.]com


I reached my goal, now we have the C2 URL from the article: `castechtools[.]com`!
