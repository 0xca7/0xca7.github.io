---
title: "Battling with APT malware"
date: 2024-01-01T10:00:43+01:00
draft: false
---

When I read malware analysis reports, I try to replicate them. That means I skim
the report, if the malware is interesting, I get a sample and dig into it. When I
get stuck, I go back to the report for help. I came across an interesting analysis  of an APT malware: https://asec.ahnlab.com/en/57684/. 

As a target I decided to look at the dropper component:

```
MD5: 1ecd83ee7e4cfc8fed7ceb998e75b996
SHA256: eff3e37d0406c818e3430068d90e7ed2f594faa6bb146ab0a1c00a2f4a4809a5
```

The report covers a lot of ground and explains the workings of the malware perfectly.
During my reversing work, I produced two results/details that may add to the findings.

### String "Encryption"

The obfuscation of the strings in the malware is not a simple, standard XOR. Instead, it is a more complicated operation as shown in the following listing:

```c
char __cdecl sub_402C80(int *a_key, int a_data, int a_size)
{
  char result; // al
  int v4; // ecx
  int v5; // edx
  int v6; // ecx
  int byte; // edx
  char v8; // cl
  char v9; // al
  int i; // ecx
  char v11; // bl
  char v12; // [esp+7h] [ebp-11h]
  int v13; // [esp+8h] [ebp-10h]
  int v14; // [esp+Ch] [ebp-Ch]
  int v15; // [esp+10h] [ebp-8h]
  int v16; // [esp+14h] [ebp-4h]

  result = (char)a_key;
  if ( a_key && a_data && a_size >= 1 )
  {
    v4 = *a_key;
    v14 = a_key[1];
    v5 = a_key[3];
    v13 = v4;
    v6 = a_key[2];
    v16 = v5;
    byte = 0;
    v15 = v6;
    result = HIBYTE(v16);
    v8 = v13;
    do
    {
      v9 = v8 ^ BYTE2(v13) ^ (BYTE2(v14) + result);
      for ( i = 15; i > 0; --i )
        *((_BYTE *)&v13 + i) = *(&v12 + i);
      v11 = *(_BYTE *)(byte + a_data);
      v8 = v9;
      result = HIBYTE(v16);
      LOBYTE(v13) = v8;
      *(_BYTE *)(byte + a_data) = HIBYTE(v16) ^ v11;
      ++byte;
    }
    while ( byte < a_size );
  }
  return result;
}
```

They key point here is that the decryption routine does not contain any parts
which cannot be emulated by a CPU emulator. The arguments to the function are
passed via the stack, consisting of the key, the encrypted data and the data size.

Using Unicorn and a small python script, this is easily emulated, as shown below:

```python
import struct
import pefile
from unicorn import *
from unicorn.x86_const import *

from capstone import *

STACK_SIZE = 0x1000
STACK_ADDR = 0x8000

SCRATCH_ADDR = 0x4000
SCRATCH_SIZE = 0x1000

class EmuSection:

    def __init__(self, name, addr_base, addr, size, data):
        self.name = name.decode("utf-8")
        self.addr_base = addr_base
        self.addr = addr
        self.size = size
        self.data = data

def load_data():

    sections = []
    pe = pefile.PE('../eff3e37d0406c818e3430068d90e7ed2f594faa6bb146ab0a1c00a2f4a4809a5')
    for section in pe.sections:
        sections.append(EmuSection(section.Name, 
            int(pe.OPTIONAL_HEADER.ImageBase), int(section.VirtualAddress),
            section.section_max_addr - section.section_min_addr, section.get_data()))

    return sections


def code_hook(uc, addr, size, usr_data):
    code = uc.mem_read(addr, size)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    esi = uc.reg_read(UC_X86_REG_ESI)
    edi = uc.reg_read(UC_X86_REG_EDI)
    for i in md.disasm(code, addr):
        # print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        if i.mnemonic == "ret":
            print("[+] caught RET, stopping.")
            uc.emu_stop()

def main():

    arg0 = struct.pack('<i', 0x0040e110)    # the key
    arg1 = struct.pack('<i', 0x00411040)    # the data
    arg2 = struct.pack('<i', 0x33a)         # datasize
    emulate(
        arg0, arg1, arg2, 0x411040, 0x33a
    )

    arg0 = struct.pack('<i', 0x40e120)  
    arg1 = struct.pack('<i', 0x4114c0)  
    arg2 = struct.pack('<i', 0x829)    
    emulate(
        arg0, arg1, arg2, 0x4114c0, 0x829
    )


def emulate(arg0, arg1, arg2, result, size):

    sections = load_data()
    code = None

    code_start = 0x2c80 - 0x1000
    code_end   = 0x2d05 - 0x1000 + 1

    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    # have this around just in case
    print("[+] init scratchmem")
    mu.mem_map(SCRATCH_ADDR, SCRATCH_SIZE, UC_PROT_ALL)
    mu.mem_write(SCRATCH_ADDR+0x1ae, g_CONFIG)

    for section in sections:
        print("[{}]> {}".format(section.name, 
            hex(section.addr + section.addr_base)))
        
        # align to pagesize for memory mapping
        aligned_size = None
        if section.size % 0x1000 == 0:
            aligned_size = section.size
        else:
            aligned_size = (section.size // 0x1000 + 1) * 0x1000

        print("[+] mapping {:x} - {} bytes (0x{:x})".format(section.addr+section.addr_base,
            section.size, aligned_size))

        mu.mem_map(section.addr + section.addr_base, aligned_size, UC_PROT_ALL)
        mu.mem_write(section.addr + section.addr_base, section.data)

    print("[+] performing stack setup")
    # setup stack
    mu.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_ALL)

    stack_start = STACK_ADDR + STACK_SIZE // 2
    mu.mem_write(stack_start, arg2)
    mu.mem_write(stack_start-4, arg1)
    mu.mem_write(stack_start-8, arg0)
    stack_start -= 12


    mu.reg_write(UC_X86_REG_ESP, stack_start)
    mu.reg_write(UC_X86_REG_EBP, stack_start)

    if ".text" in section.name:
        code = section.data[code_start:code_end]
        for byte in code:
            print("{:02x}".format(byte), end=' ')
        print()

    mu.hook_add(UC_HOOK_CODE, code_hook)

    addr = 0x402c80
    code_size = code_end - code_start

    print("[+] running emulation (a0: {} a1: {} a2: {})".format(arg0, arg1, arg2))
    mu.emu_start(addr, addr+code_size)

    data = mu.mem_read(result, size)

    print("raw data: {}\n\n\n".format(data))

    for byte in data:
        if byte == 0:
            print()
        else:
            print("{}".format(chr(byte)), end='')


if __name__ == '__main__':
    main()
```

The script above is not the cleanest, I just hacked it as fast as possible. However, it gets the job done.
Here's a part of the output, the strings are successfully decrypted:

```
\Registry\Machine\SYSTEM\CurrentControlSet\Control\WMI\Security
125463f3-2a9c-bdf0-d890-5a98b08d8898
f0012345-2a9c-bdf8-345d-345d67b542a1
cgi_config
Application 
Background 
Control 
Desktop 
Extension 
Function 
Group 
Host 
Intelligent 
Key 
Layer 
Multimedia 
Network 
Operation 
Portable
--- SNIP ---
```

The calls to the decryption function are consistent, meaning the above script can be used to decrypt any parts of the dropper by just supplying the address of key, data and the data size.

Once the strings were decrypted, I patched them into the binary, overwriting the encrypted part. As a result, the output in Binary Ninja looks pretty nice and readable:

```
--- SNIP ---
00402d6d          data_412d68 = data_412bc4(hModule, "FreeLibrary");
00402d7e          data_412bbc = data_412bc4(hModule, "CreateThread");
00402d8f          data_412c28 = data_412bc4(hModule, "GetExitCodeProcess");
00402da0          data_412d44 = data_412bc4(hModule, "TerminateProcess");
--- SNIP ---
```

There's really no need to automatically rename the global variables, for example `data_412d68` to `FreeLibrary`. Every time I encounter a function call via a global, I just look at the cross references tab and see the function name, which I then rename manually. 

### Config Extraction

As far as the configuration is concerned, the details are covered in the report. In short summary, the configuration is stored as a zip in the resource section, also containing the next stage. There is password protection for the zip, with the password stored as an ASCII string in the dropper binary. Extracting the config is a simple process:

1. extract the zip from the resource section (.rsrc) by using the zip magic
2. get all strings from the binary, one of them is the password
3. try to unzip with all of the strings, one string must successfully unzip the data
4. the smaller of the two files is the config, read and parse it (structure given in the report)
5. output the config

Again, I hacked up a simple python script that does the work:


```python
import os
import sys
import pefile
from os import walk
from zipfile import ZipFile

FILEPATH='../eff3e37d0406c818e3430068d90e7ed2f594faa6bb146ab0a1c00a2f4a4809a5'

"""
extract the resource section
"""
def extract_rsrc():
    pe = pefile.PE(FILEPATH)
    for section in pe.sections:
        if b"rsrc" in section.Name:
            return section.get_data()

"""
collect strings in the binary
"""
def get_strings():
    
    strings = []
    temp = []
    with open(FILEPATH, "rb") as f:
        data = f.read()
        for byte in data:
            if byte >= 0x20 and byte <= 0x7e:
                temp.append(byte)
            else:
                if len(temp) > 5:
                    s = ''.join(chr(e) for e in temp)
                    strings.append(s)
                temp = []
    return strings

def main():

    # get the resource section and strings
    rsrc = extract_rsrc()
    strings = get_strings()

    # find the zipfile in the resource section
    ZIPMAGIC = b"\x50\x4b\x03\x04"
    idx = rsrc.find(ZIPMAGIC)
    rsrc = rsrc[idx:]

    # create the output directory
    os.mkdir("out")

    # write the zipfile to disk
    with open("out/extracted_zip.zip", "wb") as f:
        f.write(rsrc)

    # now try all of the strings until we find the one that is the ZIP password
    with ZipFile("out/extracted_zip.zip") as zf:
        for string in strings:
            try:
                zf.extractall(path="out/", pwd=bytes(string, "utf-8"))
                print("extracted with pwd: {}".format(string))
                break
            except:
                pass

    # collect the files we extracted
    files = []
    for (dirpath, dirnames, filenames) in walk("out/"):
        files.extend(filenames)
        break # need only toplevel

    # now find the smallest of the files, which contains the config
    MIN_SIZE = sys.maxsize
    MIN_FILE = ""
    for file in files:
        with open("out/" + file, "rb") as f:
            size = len(f.read())
            if MIN_SIZE > size:
                MIN_SIZE = size
                MIN_FILE = file

    print("smallest file stores the config: {}".format(MIN_FILE))

    # decode the config. IP addresses start at offset 0x12
    # read 8 bytes at a time, 4 bytes for the IP 4 bytes for the port
    # 
    # (sidenote: a port is at most 0xffff, why store 4 bytes!?
    #            2 bytes are wasted)
    #
    # print all of the IPs and ports (defanged)
    with open("out/" + MIN_FILE, "rb") as f:
        data = f.read()
        data = data[0x12:] # this is where the IPs and ports start

        for i in range(0, len(data)-8, 8):

            if data[i:i+8] == b'\x00\x00\x00\x00\x00\x00\x00\x00':
                break
            ip = data[i:i+4]
            port = data[i+4:i+8]

            print("IP: {}[.]{}.{}.{} Port: {}".format(
                ip[0], ip[1], ip[2], ip[3], int(port[0] << 8 | port[1])))


if __name__ == '__main__':
    main()
```

The output is as follows:

```
extracted with pwd: !1234567890 dghtdhtrhgfjnui$%^^&fdt
smallest file stores the config: Config.cpl
IP: 103[.]16.223.35 Port: 36895
IP: 113[.]28.244.194 Port: 36895
IP: 116[.]48.145.179 Port: 36895
IP: 186[.]116.9.20 Port: 16415
IP: 186[.]149.198.172 Port: 36895
IP: 186[.]67.71.97 Port: 36895
IP: 195[.]28.91.232 Port: 38943
IP: 195[.]97.97.148 Port: 36895
IP: 199[.]15.234.120 Port: 36895
IP: 200[.]42.69.133 Port: 36895
IP: 203[.]131.222.99 Port: 36895
IP: 210[.]187.87.181 Port: 36895
IP: 83[.]231.204.157 Port: 38943
IP: 84[.]232.224.218 Port: 38943
IP: 89[.]190.188.42 Port: 36895
```

### Conclusion

Automation with a little python magic gets a whole lot done. Decrypting the strings
and using the cross references tab in binja makes the malware readable and the config is easily extracted using pefile and ZipFile.

Thanks to ahnlab for the amazing report :)