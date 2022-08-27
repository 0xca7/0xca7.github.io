---
title: "Calling Conventions"
date: 2022-08-26T20:56:15+02:00
draft: false
---

This is a small overview of calling conventions regarding the x86 and x86_64
architectures, both for Windows and Linux

---

## Windows

The `stdcall` calling convention ... the callee is responsible for cleaning up the stack, but the *parameters are pushed onto the stack in right-to-left order*, as in the `_cdecl` calling convention (here: caller must clean up the stack). Registers EAX, ECX, and EDX are designated for use within the function. Return values are stored in the EAX register.

stdcall is the standard calling convention for the Microsoft Win32 API.

### x86

On x86 platforms, all arguments are widened to 32 bits when they are passed. Return values are also widened to 32 bits and returned in the EAX register, except for 8-byte structures, which are returned in the EDX:EAX register pair. Larger structures are returned in the EAX register as pointers to hidden return structures. Parameters are pushed onto the stack from right to left.

### x86_64

Integer arguments are passed in registers `RCX, RDX, R8, and R9`. Floating point arguments are passed in `XMM0L, XMM1L, XMM2L, and XMM3L`

The first four arguments are placed onto the registers. That means RCX, RDX, R8, R9 for integer, struct or pointer arguments (in that order), and XMM0, XMM1, XMM2, XMM3 for floating point arguments. Additional arguments are pushed onto the stack (right to left).

## Linux

### Systemcalls

https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md

Note: this is only relevant for system calls, not for function calls.
![63f534ca3a5d4b59092d79d7d6f57fe2.png](:/74b3ee207583442597df011ef8699eb5)


### x86

In x86-32 parameters were passed on stack. Last parameter was pushed first on to the stack until all parameters are done and then call instruction was executed. This is used for calling C library (libc) functions on Linux from assembly.

### x86_64

The first six integer or pointer arguments are passed in registers RDI, RSI, RDX, RCX, R8, R9 (R10 is used as a static chain pointer in case of nested functions[25]: 21 ), while XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6 and XMM7 are used for the first floating point arguments.[25]: 22  As in the Microsoft x64 calling convention, additional arguments are passed on the stack.

see this for great detailed explanation:
https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f




