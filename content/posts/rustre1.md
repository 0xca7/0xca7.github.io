---
title: "Rust Reversing - Iterators"
date: 2024-06-22T10:58:55+02:00
draft: false
---

![logo](/static/rre_small.png)

# Prerequisites

I'll use Ghidra 11.0.2 for reversing, all binaries are built on Linux x86_64. Doesn't matter which disassembler you use, Binja, IDA, Ghidra, neither does the OS Windows, Linux or Mac, doesn't matter either. So, if you want to follow along, feel free to use any setup you want. It helps to know a bare minimum about Rust. If you don't, at least you should know C :)

For cargo and rustc, I have the following versions:

```
[~]$ cargo --version
cargo 1.78.0 (54d8815d0 2024-03-26)
[~]$ rustc --version
rustc 1.78.0 (9b00956e5 2024-04-29)
```

All prebuilt executables for this post can be found in my git repository **rust-re** (https://github.com/0xca7/rust-re) in the `prebuilt` folder. I put them all in zip file `iterators_prebuilt.zip`.

# Introduction

A common scheme you see in malware and firmware is XOR encryption. Although 
weak and sparking furious debates if it should even be called *encryption*,
it is often used to make analysis harder/annoying. In malware it's often used to hide
strings, in firmware I've seen it used to encrypt whole blobs or even SPI
communications.

In it's simplest form you'd see something like this in C:

```c
/**
 * @brief decrypts/encrypts bytes in place
 * @param p a buffer holding bytes to decrypt/encrypt
 * @param s the size of the buffer in bytes
 * @return void
 */
void
crypt_xor_in_place(uint8_t *p, size_t s)
{
    size_t i = 0;
    uint8_t xor_key = 0xde;

    for(i = 0; i < s; i++)
    {
        p[i] ^= xor_key;
    }
}
```

The encrypted string goes in as `p` with size `s` and is decrypted in place.
Seeing this in assembly corresponds pretty much to what you would expect.

Let's do this in Rust now, with iterators.

# Rust Iterators

So, what is an iterator? If you ask Wikipedia, it says "an object that enables
a programmer to traverse a container". That about sums it up. For example, a 
container in Rust could be a simple vector, a slice, whatever.

Here is how you *could* code the `crypt_xor_in_place` function in rust, with 
iterators:

```rust
fn crypt(data: &mut [u8]) {
    data
        .iter_mut()
        .for_each(|x| *x ^= 0xde);
}
```

I'll break what this function actually says, step-by-step:

`data: &mut [u8]`

- give me a slice `&` of type `u8`.
- I want to be able to change the slice `&mut`

`data.iter_mut()`

- give me an iterator of `data`, where I can change the elements contained in
  `data` (`iter_mut` yields the mutable iterator)

`data.iter_mut().for_each( f )`

- now that we have a mutable iterator, we apply a function `f` to each element
  in the iterator (`for_each`), this function can change the element because 
  of `iter_mut`

`|x| *x ^= 0xde`

- this is a *closure* passed to `for_each`, it's the function that will be 
  applied.
- we call an element of `data` by the name `x` 
- `x` is a reference to a `u8`, thus `&u8`, that's we we need to dereference
  with `*x` to actually make the change.
- the change is just: `x = x XOR 0xde`

Doing the encryption like this is functional programming approach that is common in Rust. Instead of using a for loop, you can do this. Generally, when I code rust, I mostly take this approach, it's just more comfy.

# Reverse Engineering

I compiled two versions, a `debug` and a `release` build. The debug build
contains symbols, names and everything else you want to have from debug build.

For the `release` build, I specified it should be stripped [1]. This is the
build that you'd actually ship. 

Now here's a little catch: When you build your Rust project with `cargo build` you get the debug build, not the release build. As such, it can happen that you get hold of a debug binary instead of a release binary. I will cover both cases.

## Debug Build

In the debug build, Ghidra will show pretty much everything you want to know. Finding the main function is also no problem. In the symbol tree, you can find `crypt::crypt::main` under `Namespaces`. The only thing that is interesting to us is `crypt::crypt::crypt`. You get there via `Namespaces` or by the call in `crypt::crypt::main`.

Here's the disassembly of `crypt::crypt::crypt`:

```
                    ********************************************
                    * DWARF original prototype: void crypt(... *
                    ********************************************
                    char * __rustcall crypt(char * __key, c
         char *       RAX:8     <RETURN>
         char *       RDI:8     __key
         char *       RSI:8     __salt
         undefined8   Stack[-0x local_8                     XREF[1]: 00108f29(W)  
         undefined8   Stack[-0x local_10                    XREF[1]: 00108f24(W)  
                    _ZN5crypt5crypt17h9a2969e463138a  XREF[4]: main:00108fe7(c), 
                    crypt::crypt::crypt                        main:00109225(c), 
                                                               0014ebf8, 0014fde8(*)  
   00108f20 48 83      SUB     RSP,0x18
            ec 18
                       // save first argument = data_ptr
   00108f24 48 89      MOV     qword ptr [RSP + local_10],RDI
            7c 24 08
                       // save second argument = data_length
   00108f29 48 89      MOV     qword ptr [RSP + local_8],RSI
            74 24 10
                       // create a mutable iterator from the slice passed in
   00108f2e e8 1d      CALL    core::slice::iter_mut<u8>         IterMut<u8> iter_mut<u
            f7 ff ff
   00108f33 48 89 c7   MOV     RDI,RAX
   00108f36 48 89 d6   MOV     RSI,RDX
                       // iterate and apply the closure for each element in the iterator
   00108f39 e8 a2      CALL    core::slice::iter::for_each<>     void for_each<u8,_cryp
            15 00 00
   00108f3e 48 83      ADD     RSP,0x18
            c4 18
   00108f42 c3         RET

```

The decompiler does a good job here:

```c
char * __rustcall crypt::crypt::crypt(char *__key,char *__salt)
{
  char *pcVar1;
  IterMut<u8> IVar2;
  &mut_[u8] self;
  
  self.length = (usize)__salt;
  self.data_ptr = (u8 *)__key;
  IVar2 = core::slice::iter_mut<u8>(self);
  pcVar1 = (char *)core::slice::iter::for_each<>(IVar2.ptr.pointer,IVar2.end_or_len);
  return pcVar1;
}
```

So, `IVar2` is the mutable iterator. Our data length is called `salt` for some reason, `key` is the data pointer.
The slice `&mut [u8]` consists of a length and a pointer to the data, as one would expect [2].

Now, where is the XOR operation? It can be found inside of `core::slice::iter::for_each<>`. Let's look inside:

```c
void __rustcall core::slice::iter::for_each<>(u8 *param_1,u8 *param_2)
{
  u8 *x;
  IterMut<u8> local_40;
  {closure_env#0} local_29;
  Option<&mut_u8> local_28;
  Option<&mut_u8> local_20;
  Option<&mut_u8> local_8;
  
  local_40.ptr.pointer = param_1;
  local_40.end_or_len = param_2;
                    /* try { // try from 0010a4ee to 0010a4f7 has its CatchHandler @ 0010a508 */
  while (local_28 = next<u8>(&local_40), local_28 != (Option<&mut_u8>)0x0) {
                    /* try { // try from 0010a54f to 0010a558 has its CatchHandler @ 0010a508 */
    local_20 = local_28;
    local_8 = local_28;
    crypt::crypt::{closure#0}(&local_29,(u8 *)local_28);
  }
  return;
}
```

We'll break it down:

- `local_28` is the next element in the iterator. You can see this because of `local_28 = next<u8>`
- when an iterator has no next element, that is, the iterator reached the end, it will return `None`

You might find `None` being something you are not familiar with. To explain what `None` is, we first need to understand the `enum` type in Rust. This type can be used just like a C enum, but I can do a lot more. In C, you would have something like:

```c
enum Level {
  LOW,
  MEDIUM,
  HIGH
};
```

In Rust, you can, among other things, assign values to enum items. For example:

```rust
pub enum Option<T> {
    None,
    Some(T),
}
```

Here, `T` describes the type, for example, we could have `Option<String>`, `Option<u32>`, etc. The enum you can see above is the `Option` enum, a standard enum that comes with Rust. You can find this everywhere in Rust programs. In the case of the iterator, if the iterator can return a value (there is a *next* element), it will return `Some(T)`. The `Some` tells us that we got *some* value back. If the iterator is not able to yield anymore items, for example, if a list is iterated and the end is reached, we would get `None` back.

- the `local_28 != (Option<&mut u8>0x0)` checks if the next element is `None`, this serves to determine when to stop looping with `while`.

Our actual call to the closure which applies the XOR operation to an element is in `crypt::crypt::{closure#0}`.
Inside here, we find the XOR operation applied to an element `x`:

```c
void __rustcall crypt::crypt::{closure#0}({closure_env#0} *param_1,u8 *x)
{
  {closure_env#0} *param_0-local;
  u8 *x-local;
  
  *x = *x ^ 0xde;
  return;
}
```

As you can see from this, we can drill down into the debug build the find the operation applied to each element of the slice. From this, it's easy to understand what is happening and we can deduce that we're dealing with XOR encryption.

Don't worry, we'll cover a more complicated case later :)

## Release Build

I'm not gonna cover how to find the main. If you're following along, it's here: `0x00108720`.

Here, it gets interesting:

```c
--- SNIP ---

  // [TAG#0]
  FUN_0011fd70(&local_90,"plaintext.txt",0xd);
  // [TAG#1]
  if (local_90 == (undefined4 *)0x8000000000000000) {
    local_d8 = uStack_88;
                    /* try { // try from 00108ad6 to 00108af8 has its CatchHandler @ 00108b62 */
    FUN_001082b0("failed to read data",0x13,&local_d8,&PTR_FUN_001552c8,&PTR_s_src/main.rs_001552e8)
    ;
    goto LAB_00108b27;
  }

  // [TAG#2]
  local_48 = (ulong)local_80;
  local_58 = (undefined4)local_90;
  uStack_54 = local_90._4_4_;
  uStack_50 = (undefined4)uStack_88;
  uStack_4c = uStack_88._4_4_;

  if (local_80 != (undefined4 ***)0x0) {
    ppuVar10 = uStack_88;

    // [TAG#3]
    if (7 < local_80) {
      if (local_80 < 0x20) {
        uVar9 = 0;
      }
      else {
        uVar9 = (ulong)local_80 & 0xffffffffffffffe0;
        uVar11 = 0;
        do {
          // [TAG#5]
          puVar1 = (ulong *)((long)uStack_88 + uVar11);
          puVar2 = (ulong *)((long)uStack_88 + uVar11 + 0x10);
          uVar7 = *(uint *)(puVar2 + 1);
          uVar8 = *(uint *)((long)puVar2 + 0xc);
          auVar4._8_4_ = *(uint *)(puVar1 + 1) ^ 0xdededede;
          auVar4._0_8_ = *puVar1 ^ 0xdededededededede;
          auVar4._12_4_ = *(uint *)((long)puVar1 + 0xc) ^ 0xdededede;
          *(undefined (*) [16])((long)uStack_88 + uVar11) = auVar4;
          auVar6._8_4_ = uVar7 ^ 0xdededede;
          auVar6._0_8_ = *puVar2 ^ 0xdededededededede;
          auVar6._12_4_ = uVar8 ^ 0xdededede;
          *(undefined (*) [16])((long)uStack_88 + uVar11 + 0x10) = auVar6;
          uVar11 = uVar11 + 0x20;
        } while (uVar9 != uVar11);
        if (local_80 == (undefined4 ***)uVar9) goto LAB_0010881b;
        if (((ulong)local_80 & 0x18) == 0) {
          ppuVar10 = (undefined **)((long)uStack_88 + uVar9);
          goto LAB_0010880a;
        }
      }
      // [TAG#4]
      uVar11 = (ulong)local_80 & 0xfffffffffffffff8;
      ppuVar10 = (undefined **)((long)uStack_88 + uVar11);
      do {
        *(ulong *)((long)uStack_88 + uVar9) =
             *(ulong *)((long)uStack_88 + uVar9) ^ 0xdededededededede;
        uVar9 = uVar9 + 8;
      } while (uVar11 != uVar9);
      if (local_80 == (undefined4 ***)uVar11) goto LAB_0010881b;
    }
LAB_0010880a:
    // [TAG#3]
    do {
      *(byte *)ppuVar10 = *(byte *)ppuVar10 ^ 0xde;
      ppuVar10 = (undefined **)((long)ppuVar10 + 1);
    } while (ppuVar10 != (undefined **)((long)uStack_88 + (long)local_80));
  }
LAB_0010881b:
--- SNIP ---
```

To break this down, I'll add tags to the above in the form: `// [TAG#x]`.

The program reads a file `plaintext.txt`, in addition to the file name, the length of the file name `0xd` is passed to the reader function. The first parameter is `local_90` `[TAG#0]`. This is checked for an error return `[TAG#1]`. Next, we have a sequence of assignments `[TAG#2]`. From the context, you can clearly see that `local_80` must be the length of the vector that was read (`local_80` is continuously checked against integers values).

The length is used to determine how to process the data with the XOR operation.

- `[TAG#3]` will be executed when the length of the vector is less or equal 7 bytes. It will also be executed for remaining bytes.
- `[TAG#4]` handles the case where we have less than 32 bytes or we have more than 32 bytes and a remainder.
- `[TAG#5]` is the case when we have greater or equal 32 bytes 

You get the idea. The XOR encryption was optimized. The important thing to note here is that the iterator is gone. You can't see it in the disassembler. Instead, you get optimized loops for different lengths of the input to process. There is no function call to `crypt` anymore. It's all in the main.

# Another Algorithm

The next algorithm does a little more than just a byte-wise XOR. I uses a counter value that is also processed. As pseudocode:

```
for i in 0..length 
do
  data[i] = data[i] ^ XOR_KEY ^ (i MOD 256)
end for
```

In Rust we can do it like this:

```rust
fn crypt_counter(data: &mut [u8]) {
    data
        .iter_mut()
        .enumerate()
        .for_each(|(i, x)| *x ^= 0xde ^ i as u8);
}
```

Pretty similar to what we had before. The only thing that changed is the `enumerate()` before `for_each`, which results in `for_each` now having a tuple as an argument. So, the closure now receives a counter value `i`, that is the index of `x` in `data`, as an addition. The operation applied to `data` corresponds to what we defined in the pseudocode.

## Reversing the Debug Version

Let's start off with the debug version and check out the new function. We can use the namespaces in the symbol tree to find the function we want to analyze as before. Here, we can find `crypt_counter::crypt_counter::main`. You can clearly see the call to the `crypt_counter::crypt_counter::cryptcounter` function we are interested in. Here, is the inside of that function, as supplied by Ghidra's decompiler:

```c
void __rustcall crypt_counter::crypt_counter::crypt_counter(&mut_[u8] data)
{
  IterMut<u8> self;
  Enumerate<> EStack_28;
  u8 *local_10;
  usize local_8;
  
  local_8 = data.length;
  local_10 = data.data_ptr;
  self = core::slice::iter_mut<u8>(data); // [TAG#0]
  core::iter::traits::iterator::Iterator::enumerate<>(&EStack_28,self); // [TAG#1]
  core::iter::traits::iterator::Iterator::for_each<>(&EStack_28);
  return;
}
```

We can see the added `enumerate()` (`[TAG#1]`). This tells us that we have a counter, corresponding to the element inside `data` and a tuple argument in the closure of `for_each()`. We know that the corresponding element must be of type `u8` from `[TAG#0]`. When we start digging into `for_each`, we need to be aware of this.

Inside `for_each` we get this:

```c
undefined8 __rustcall core::iter::traits::iterator::Iterator::for_each<>(void)
{
  undefined8 in_RAX;
  
  adapters::enumerate::fold<>();
  return in_RAX;
}
```

Now that's different from what we saw before. There is a call to `fold()`. Again, something we know from functional programming. A fold is described in [3][4], if you don't know what fold does, here's a quick explanation:

- fold can transform a collection into a single value.
- to use fold, we need three things: an initial value, a collection and a function.
- a fold holds something called an `accumulator`. the initial value is the starting value of the accumulator.
- the function returns a value of the type that is iterated.
- a simple example: calculate a sum

```
// calculate the sum of 1,2,3,4
// initial value for the accumulator: 0
// function to apply: |acc, num| acc + num (acc is the accumulator)
// collection: range of numbers 1..4
let sum = (1..=4).fold(0, |acc, x| { acc + x });
```

Imagine we just ignore the accumulator. Then we can do our encryption like this:

```rust
data
  .iter_mut()
  .enumerate()
  .fold(0, |acc, (i, x)| { *x ^= 0xde ^ i as u8; 0 } );
```

Which is equivalent to using `for_each`. Now we can see why we have a `fold` here.
Let's continue.


Into `fold` we go! We see this, there is some data being passed in:

```c
void __rustcall
core::iter::adapters::enumerate::fold<>
          (IterMut<u8> *self,undefined8 param_2,undefined8 param_3,{closure_env#0}<> param_4)
{
  slice::iter::fold<>(*self,(char)self[1].ptr.pointer,param_4);
  return;
}
```

... one layer below that, again, going into `fold`:

```c
void __rustcall core::slice::iter::fold<>(IterMut<u8> self,undefined init,{closure_env#0}<> f)

{
  undefined7 in_register_00000011;
  usize rhs;
  NonNull<u8> end_1;
  usize i;
  usize len;
  () acc;
  NonNull<u8> end;
  NonNull<u8> local_b8;
  u8 *local_b0;
  undefined8 local_a8;
  undefined local_99;
  u8 *local_98;
  usize local_90;
  usize local_88;
  u8 *local_80;
  u8 *local_78;
  undefined local_6c;
  undefined local_6b;
  u8 **local_68;
  u8 **local_60;
  u8 **local_58;
  NonNull<u8> local_50;
  u8 *local_48;
  u8 **local_40;
  u8 *local_38;
  NonNull<u8> local_30;
  u8 *local_18;
  usize local_10;
  usize local_8;
  
  local_b0 = self.end_or_len;
  local_b8 = self.ptr;
  local_a8 = CONCAT71(in_register_00000011,init);
  local_68 = &local_b0;
  local_60 = &local_b8.pointer;
  local_58 = &local_98;
  // [TAG#1]
  local_99 = local_b8.pointer == local_b0;
  if (!(bool)local_99) {
    local_6b = 0;
    local_6c = 1;
    local_90 = 0;
    local_40 = &local_b0;
    local_98 = local_b0;
    local_50.pointer = local_b8.pointer;
    local_48 = local_b0;
    local_38 = local_b0;
    local_30.pointer = local_b8.pointer;
                    /* try { // try from 001093eb to 00109461 has its CatchHandler @ 00109406 */
    // [TAG#2]
    local_88 = ptr::const_ptr::sub_ptr<u8>(local_b0,local_b8.pointer);
    do {
      local_6c = 0;
      local_18 = local_b8.pointer;
      local_10 = local_90;
      local_80 = local_b8.pointer + local_90;
      local_78 = local_80;
      // [TAG#3]
      core::iter::adapters::enumerate::fold::enumerate::{closure#0}<>((char)&local_a8,local_80); // [TAG#0]
      local_8 = local_90;
      local_90 = local_90 + 1;
    } while (local_90 != local_88);
  }
  return;
}
```

Now we finally see our closure! I marked it with `[TAG#0]` in the listing above. Before we get into the closure itself, let's spend some more time figuring out what is going on. At `[TAG#1]`, the pointer to the data is checked. If it has reached the end of the data (condition `local_99` evaluates to true), we're done. In any other case, iteration starts. The variable `local_90` is just a counter. This is compared in the while loop with `local_88`, which is just the number of elements in the collection we're iterating. You can see this from `[TAG#2]`. Here, `sub_ptr` is used to calculate the distance between the end of the collection and the current pointer, which will point to the first element.

The actual calculation is done in the closure at `[TAG#3]`. The arguments to this are `local_80`, which is the current element. The first argument, `local_a8` is most likely the accumulator, initialized to an initialization value at the start of the function. We don't care about the initialization value.

Next, we get into the closure `core::iter::adapters::enumerate::fold::enumerate::{closure#0}<>(..)`. I will expand the other nested functions as well below, to get a better overview.

```c
void __rustcall core::iter::adapters::enumerate::fold::enumerate::{closure#0}<>(char acc,u8 *item)
{
  // [TAG#0]
  (usize,_&mut_u8) item_00;
  undefined7 in_register_00000039;
  usize *puVar1;
  usize *count;
  () acc_1;
  
  puVar1 = (usize *)CONCAT71(in_register_00000039,acc);
  // [TAG#1]
  item_00.__1 = item;
  item_00.__0 = *puVar1;
  traits::iterator::Iterator::for_each::call::{closure#0}<>(acc + 0x8,item_00);
  // #[TAG#2]
  if (*puVar1 != 0xffffffffffffffff) {
    *puVar1 = *puVar1 + 1;
    return;
  }
                    /* try { // try from 00108737 to 00108752 has its CatchHandler @ 0010875f */
                    /* WARNING: Subroutine does not return */
  panicking::panic();
}

void __rustcall
core::iter::traits::iterator::Iterator::for_each::call::{closure#0}<>
          (undefined param_1,(usize,_&mut_u8) item)
{
  undefined7 in_register_00000039;
  {closure_env#0} *f;
  
  // [TAG#3]
  crypt_counter::crypt_counter::{closure#0}
            (({closure_env#0} *)CONCAT71(in_register_00000039,param_1),item);
  return;
}

void __rustcall
crypt_counter::crypt_counter::{closure#0}({closure_env#0} *param_1,(usize,_&mut_u8) param_2)
{
  {closure_env#0} *param_0-local;
  (usize,_&mut_u8) param_1-local;
  usize i;
  u8 *x;
  // [TAG#4]
  *param_2.__1 = param_2.__0 ^ 0xde ^ *param_2.__1;
  return;
}

```

Now, we can get a better picture of what is happening. Our tuple of the index and the current element is at `[TAG#0]`. As expected, the tuple passed to the function is in `item00.__1` that is the `u8` in the tuple. The current index, `item00.__0` is `puVar1` - the accumulator - and incremented after the `for_each` call at `[TAG#2]`. This is an argument for the function `core::iter::traits::iterator::Iterator::for_each::call::{closure#0}`. Inside here, at `[TAG#3]`, is the final call down to the actual logic inside the closure `crypt_counter::crypt_counter::{closure#0}`. After following all nested functions, we finally see `*x = *x ^ 0xde ^ i` at `[TAG#4]`.

As you can see, it's possible to follow what is happening in the debug version, but lots if nesting makes it convoluted and a harder to follow what is going on. Currently, there is still something missing in my understanding: why is `0x8` added to `acc` in the parameter to the `for_each` call? One reason for that might be that `acc` is a structure, consisting of multiple members, thus the offset will access a certain member. Also, notice that this value, `acc+0x8` is not actually used inside of `crypt_counter::crypt_counter::{closure#0}`. However, the accumulator `acc` is incremented to store the current index. I think with this we can safely say that we can see the XOR operation with the index `i` applied to the data in the iterator, giving us an understanding to reverse the encryption.

Let's move on to the release version.

## Reversing the Release Version

This time, I will post the full main function decompiled by Ghidra:

```c
void FUN_00108700(void)

{
  byte *pbVar1;
  byte *pbVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  byte bVar10;
  byte bVar11;
  byte bVar12;
  byte bVar13;
  byte bVar14;
  byte bVar15;
  byte bVar16;
  byte bVar17;
  long lVar18;
  ulong uVar19;
  ulong uVar20;
  byte bVar21;
  undefined uVar24;
  byte bVar25;
  byte bVar26;
  undefined uVar27;
  byte bVar28;
  byte bVar29;
  byte bVar30;
  byte bVar31;
  byte bVar32;
  byte bVar33;
  byte bVar34;
  byte bVar35;
  byte bVar36;
  byte bVar37;
  byte bVar38;
  byte bVar39;
  undefined auVar22 [16];
  undefined auVar23 [16];
  byte bVar40;
  undefined4 local_98;
  undefined4 uStack_94;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  ulong local_88;
  undefined **local_80;
  undefined8 local_78;
  undefined **local_70;
  undefined8 local_68;
  undefined8 *local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined4 uStack_48;
  undefined4 uStack_44;
  ulong local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined local_20;
  undefined4 *local_18;
  code *local_10;
  
  // [TAG#0]
  FUN_0011fb10(&local_50,&DAT_00146480,0xd);
  if (local_50 == -0x8000000000000000) {
                    /* try { // try from 0010882c to 00108850 has its CatchHandler @ 00108853 */
    FUN_001082b0(&DAT_0014648d,0x18,&local_80,&PTR_FUN_00155320,&PTR_DAT_00155340);
    do {
      invalidInstructionException();
    } while( true );
  }
  local_88 = local_40;
  local_98 = (undefined4)local_50;
  uStack_94 = local_50._4_4_;
  uStack_90 = uStack_48;
  uStack_8c = uStack_44;
  if (local_40 != 0) {
    // [TAG#1]
    lVar18 = CONCAT44(uStack_44,uStack_48);
    if (local_40 < 8) {
      uVar19 = 0;
    }
    else {
      if (local_40 < 0x10) {
        uVar19 = 0;
LAB_0010876f:
        uVar24 = (undefined)(uVar19 >> 0x10);
        uVar27 = (undefined)(uVar19 >> 0x18);
        auVar22[7] = uVar27;
        auVar22[6] = uVar27;
        auVar22[5] = uVar24;
        auVar22[4] = uVar24;
        uVar24 = (undefined)(uVar19 >> 8);
        auVar22[3] = uVar24;
        auVar22[2] = uVar24;
        auVar22[0] = (undefined)uVar19;
        auVar22[1] = auVar22[0];
        auVar22._8_8_ = 0;
        auVar22 = pshuflw(auVar22,auVar22,0);
        uVar20 = uVar19;
        auVar22 = auVar22 | _DAT_00146030;
        do {
          *(ulong *)(lVar18 + uVar20) =
               *(ulong *)(lVar18 + uVar20) ^ auVar22._0_8_ ^ 0xdededededededede;
          uVar20 = uVar20 + 8;
          auVar23[0] = auVar22[0] + '\b';
          auVar23[1] = auVar22[1] + '\b';
          auVar23[2] = auVar22[2] + '\b';
          auVar23[3] = auVar22[3] + '\b';
          auVar23[4] = auVar22[4] + '\b';
          auVar23[5] = auVar22[5] + '\b';
          auVar23[6] = auVar22[6] + '\b';
          auVar23[7] = auVar22[7] + '\b';
          auVar23[8] = auVar22[8];
          auVar23[9] = auVar22[9];
          auVar23[10] = auVar22[10];
          auVar23[11] = auVar22[11];
          auVar23[12] = auVar22[12];
          auVar23[13] = auVar22[13];
          auVar23[14] = auVar22[14];
          auVar23[15] = auVar22[15];
          uVar19 = local_40 & 0xfffffffffffffff8;
          auVar22 = auVar23;
          if ((local_40 & 0xfffffffffffffff8) == uVar20) goto LAB_001088a6;
        } while( true );
      }
      uVar19 = local_40 & 0xfffffffffffffff0;
      // [TAG#3]
      bVar21 = 0;
      bVar25 = 1;
      bVar26 = 2;
      bVar28 = 3;
      bVar29 = 4;
      bVar30 = 5;
      bVar31 = 6;
      bVar32 = 7;
      bVar33 = 8;
      bVar34 = 9;
      bVar35 = 10;
      bVar36 = 0xb;
      bVar37 = 0xc;
      bVar38 = 0xd;
      bVar39 = 0xe;
      bVar40 = 0xf;
      uVar20 = 0;
      do {
        pbVar1 = (byte *)(lVar18 + uVar20);
        bVar3 = pbVar1[1];
        bVar4 = pbVar1[2];
        bVar5 = pbVar1[3];
        bVar6 = pbVar1[4];
        bVar7 = pbVar1[5];
        bVar8 = pbVar1[6];
        bVar9 = pbVar1[7];
        bVar10 = pbVar1[8];
        bVar11 = pbVar1[9];
        bVar12 = pbVar1[10];
        bVar13 = pbVar1[0xb];
        bVar14 = pbVar1[0xc];
        bVar15 = pbVar1[0xd];
        bVar16 = pbVar1[0xe];
        bVar17 = pbVar1[0xf];
        pbVar2 = (byte *)(lVar18 + uVar20);
        *pbVar2 = *pbVar1 ^ bVar21 ^ 0xde;
        pbVar2[1] = bVar3 ^ bVar25 ^ 0xde;
        pbVar2[2] = bVar4 ^ bVar26 ^ 0xde;
        pbVar2[3] = bVar5 ^ bVar28 ^ 0xde;
        pbVar2[4] = bVar6 ^ bVar29 ^ 0xde;
        pbVar2[5] = bVar7 ^ bVar30 ^ 0xde;
        pbVar2[6] = bVar8 ^ bVar31 ^ 0xde;
        pbVar2[7] = bVar9 ^ bVar32 ^ 0xde;
        pbVar2[8] = bVar10 ^ bVar33 ^ 0xde;
        pbVar2[9] = bVar11 ^ bVar34 ^ 0xde;
        pbVar2[10] = bVar12 ^ bVar35 ^ 0xde;
        pbVar2[0xb] = bVar13 ^ bVar36 ^ 0xde;
        pbVar2[0xc] = bVar14 ^ bVar37 ^ 0xde;
        pbVar2[0xd] = bVar15 ^ bVar38 ^ 0xde;
        pbVar2[0xe] = bVar16 ^ bVar39 ^ 0xde;
        pbVar2[0xf] = bVar17 ^ bVar40 ^ 0xde;
        // [TAG#4]
        uVar20 = uVar20 + 0x10;
        bVar21 = bVar21 + 0x10;
        bVar25 = bVar25 + 0x10;
        bVar26 = bVar26 + 0x10;
        bVar28 = bVar28 + 0x10;
        bVar29 = bVar29 + 0x10;
        bVar30 = bVar30 + 0x10;
        bVar31 = bVar31 + 0x10;
        bVar32 = bVar32 + 0x10;
        bVar33 = bVar33 + 0x10;
        bVar34 = bVar34 + 0x10;
        bVar35 = bVar35 + 0x10;
        bVar36 = bVar36 + 0x10;
        bVar37 = bVar37 + 0x10;
        bVar38 = bVar38 + 0x10;
        bVar39 = bVar39 + 0x10;
        bVar40 = bVar40 + 0x10;
      } while (uVar19 != uVar20);
      if (local_40 == uVar19) goto LAB_001088ab;
      if ((local_40 & 8) != 0) goto LAB_0010876f;
    }
    // [TAG#2]
    do {
      *(byte *)(lVar18 + uVar19) = *(byte *)(lVar18 + uVar19) ^ (byte)uVar19 ^ 0xde;
      uVar19 = uVar19 + 1;
LAB_001088a6:
    } while (local_40 != uVar19);
  }
LAB_001088ab:
  local_10 = FUN_00108680;
  local_50 = 2;
  local_40 = 0;
  local_38 = 2;
  local_30 = 0;
  local_28 = 0x1800000020;
  local_20 = 3;
  local_80 = &PTR_DAT_00155358;
  local_78 = 2;
  local_58 = 1;
  local_70 = (undefined **)&local_18;
  local_68 = 1;
                    /* try { // try from 00108936 to 00108940 has its CatchHandler @ 00108870 */
  local_60 = &local_50;
  local_18 = &local_98;
  FUN_001210a0(&local_80);
  if (CONCAT44(uStack_94,local_98) != 0) {
    free((void *)CONCAT44(uStack_8c,uStack_90));
  }
  return;
}
```

Clearly, the logic of the iterator was compiled as a loop once more. 

At `[TAG#0]` the second parameter is the string `plaintext.txt` - this file is read as a `Vec<u8>` to `local_50`. A vector's memory layout should look roughly like this:

```rust
struct Vec<T> {
    ptr: *mut T,
    len: usize,
    cap: usize,
}
```

However, we'll see that the layout is actually different in the code above. From the context, we can see that `local_40` seems to be the vector size. Also from the context, `lVar18` is a pointer to the vector data (`[TAG#1]`). 

The easiest way to find out what is being calculated, is by refering to the case `local_40 < 0x10`. If this is the case, we end up at `[TAG#2]`. Easy to see.

The other cases are if the size is less than 16, and especially when the size is greater or equal to 16. Here, we have the counter values defined at `[TAG#3]` and incremented at `[TAG#4]`, with data processed in blocks of 16 bytes.

# Conclusion

As we were able to determine, debug builds and release builds are vastly different. Debug builds feature multiple nested functions in the case of iterators. Here, we just started digging until we reached the bottom. A basic understanding of Rust and functional programming helped us get a better grasp of what is going on. I don't see a shortcut when it comes to reversing the iterators in the debug build. However, for release builds, where to iterators are converted to loops, it seems going for the cases `length < 8` simplifies things, at least with regards to the simple XOR encryption we were analyzing. I'm probably going to do more of these posts, so stay tuned.

# Acknowledgements

Thanks to @cxiao for reading this and giving me feedback :)

# References

[1] johnthagen [min-sized-rust](https://github.com/johnthagen/min-sized-rust?tab=readme-ov-file#strip-symbols-from-binary)

[2] rust slices [in the rust book](https://doc.rust-lang.org/book/ch04-03-slices.html)

[3] [fold](https://wiki.tcl-lang.org/page/Fold+in+functional+programming) in functional programming

[4] [fold method in Iterator](https://doc.rust-lang.org/beta/std/iter/trait.Iterator.html#method.fold)


