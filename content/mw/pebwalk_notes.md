---
title: "Notes on PEB Walking"
date: 2023-10-17T19:11:03+02:00
draft: false
---

This is more a note than it is a blog post. Recently, I followed this report about a malware named BLISTER, a current loader. This malware features a walk of the Process Environment Block (PEB) and API hashing to eventually load the functions necessary for its operation from `ntdll`. I followed this report: https://www.elastic.co/security-labs/blister-loader

As I found the report to be excellent, I aimed to replicate the findings to learn / get better at reversing. At some point, the report states that the malware "enumerates and hashes each export of ntdll..." - That means walking the PEB (Process Environment Block) and API hashing. I wanted to understand this in detail, it's been a while since I reversed this technique, so I started to dig in. Here are my notes and a comprehension of links I used to figure this out. Maybe they're helpful to someone else. Also, I wanted to share the awesome links I found explaining PEB walk etc. be sure to check the references! :)

---

Sample SHA256: `afb77617a4ca637614c429440c78da438e190dd1ca24dc78483aa731d80832c2` ()

Below, you can see the start of the PEB walk. I added numbers you can follow.

```
1  17173852  64a130000000       mov     eax, dword [fs:0x30]
   17173858  53                 push    ebx {__saved_ebx}  {0x0}
   17173859  57                 push    edi {__saved_edi}
   1717385a  8975f4             mov     dword [ebp-0xc {var_10_1}], esi  {0x0}
2  1717385d  8b400c             mov     eax, dword [eax+0xc]
3  17173860  8b401c             mov     eax, dword [eax+0x1c]
   17173863  c745e8004ab6f3     mov     dword [ebp-0x18 {v_xorkey}], 0xf3b64a00  
4  1717386a  8b5808             mov     ebx, dword [eax+0x8]  // *flink
   1717386d  8b433c             mov     eax, dword [ebx+0x3c]  // e_lfanew
   17173870  8b441878           mov     eax, dword [eax+ebx+0x78]
```

1. this fetches a pointer to the PEB, which is stored in `eax`
2. `PEB + 0x0c` is the offset inside the PEB pointing to `PPEB_LDR_DATA LoaderData` [1]
3. `PEB + 0x1c` is the offset inside `PEB_LDR_DATA` [2] to the variable `InInitilizationOrder`, the list of modules in initialization order
4. The list is doubly linked [3] what we have in `eax` is `*Flink` - now comes the part that got me confused: where does `eax+0x8` point to? If you look at the `LDR_MODULE` structure [4], you will see that the base address of NTDLL, which we want to fetch, is not at offset `0x8`, but at the offset `0x18` instead:

Each `LIST_ENTRY` is 8 bytes, thus, the base address SHOULD be at offset `0x18`, why use the offset `0x08` then? The blog post [2] helps out here - without it, that would've been a long debug session. We're actually `0x10` bytes into the `LDR_MODULE` struct with the `InInitalizationOrderModuleList`, thus, relatively speaking, the offset the to the base address is at `0x08`! I added the absolute and relative offsets to the struct below:

```c
typedef struct _LDR_MODULE {
/* offset */
-16   00  LIST_ENTRY              _InLoadOrderModuleList_;
-08   08  LIST_ENTRY              _InMemoryOrderModuleList_;
 00   10  LIST_ENTRY              _InInitializationOrderModuleList_;
 08   18  PVOID                   _BaseAddress_;
		  PVOID                   _EntryPoint_;
		  ULONG                   _SizeOfImage_;
		  UNICODE_STRING          _FullDllName_;
		  UNICODE_STRING          _BaseDllName_;
		  ULONG                   _Flags_;
		  SHORT                   _LoadCount_;
		  SHORT                   _TlsIndex_;
		  LIST_ENTRY              _HashTableEntry_;
		  ULONG                   _TimeDateStamp_;
} LDR_MODULE, *PLDR_MODULE;
```

Now it all makes sense. Shoutout to the author, dzzie for [2]. The PEB walk is available as C/ASM code and documented here: [5] - check it out if you want to compile a minimal version with source code to reverse and learn from. 

---

References:

[1] http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/PEB.html

[2] http://sandsprite.com/CodeStuff/Understanding_the_Peb_Loader_Data_List.html

[3] https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry

[4] http://undocumented.ntinternals.net/UserMode/Structures/LDR_MODULE.html

[5] https://github.com/jstrosch/learning-malware-analysis/blob/master/Dynamic%20Analysis/dynamic_analysis.c

0xca7

