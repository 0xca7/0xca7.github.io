---
title: "Rust Reversing - obfstr crate"
date: 2025-04-30T11:25:42+02:00
draft: false
---

Deobfuscating the obfstr Crate

The binaries for this post can be found at: `**rust-re** (https://github.com/0xca7/rust-re)`.

Alright, we're back with some more Rust RE. A while ago, I talked to @cxiao about reverse engineering
Rust binaries. It was brought to my attention that the crate `obfstr` (string obfuscation: https://crates.io/crates/obfstr) 
is a potentially interesting target for more research. Because string obfuscation is interesting when it 
comes to malware, I decided to dig into the crate and see if I would be able to reverse engineer 
a binary compiled with obfuscated strings by `obfstr`. Specifically, the `obfstr!` macro. I used
version `0.4.4` of `obfstr` for this post. Let's get started.

# Starting Point - The Program

I wrote the code below and compiled a release and debug version.

```rust
fn connect_to_c2(c2: &str) {
    println!("connecting to c2: {}", c2);
}

fn load_library(libname: &str) {
    println!("loading library: {}", libname);
}

fn main() {

    // case 1 - create &str
    load_library(obfstr::obfstr!("kernel32.dll"));

    // case 2 - create a String
    let c2 = obfstr::obfstr!("http://127.0.0.1:8000").to_owned();
    connect_to_c2(&c2);

}
```

# Release Version 

Let's start with the release version.

```
entrypoint 0x140016fc0
    __scrt_common_main_seh 0x140016e44
                           0x140016f4b --> calls what seems to be runtime init
```

```
# Listing 1
  1400012b0 48 83      SUB     RSP,0x38
            ec 38
  1400012b4 49 89 d1   MOV     R9,RDX
  1400012b7 4c 63 c1   MOVSXD  R8,ECX
  1400012ba 48 8d      LEA     RAX,[LAB_140001090]          // [TAG#1]
            05 cf 
            fd ff ff
  1400012c1 48 89      MOV     qword ptr [RSP + local_8],RAX=>L
            44 24 30
  1400012c6 c6 44      MOV     byte ptr [RSP + local_18],0x0
            24 20 00
  1400012cb 48 8d      LEA     RDX,[DAT_140019360]
            15 8e 
            80 01 00
  1400012d2 48 8d      LEA     RCX=>local_8,[RSP + 0x30]
            4c 24 30
  1400012d7 e8 24      CALL    FUN_140002f00                     
            1c 00 00
  1400012dc 90         NOP
  1400012dd 48 83      ADD     RSP,0x38
            c4 38
  1400012e1 c3         RET
```

Looks like the main function is at `0x140001090` (`[TAG#1]` in Listing 1).

With that out of the way, we need to establish what `obfstr` actually does under
the hood (it's more than just string encryption). 

## The Bowels of obfstr

This is the macro used for string encryption:

```rust
macro_rules! obfstr {
	($(let $name:ident = $s:expr;)*) => {$(
		$crate::obfbytes! { let $name = ::core::convert::identity::<&str>($s).as_bytes(); }
		let $name = $crate::unsafe_as_str($name);
	)*};
	($name:ident = $s:expr) => {
		$crate::unsafe_as_str($crate::obfbytes!($name = ::core::convert::identity::<&str>($s).as_bytes()))
	};
	($buf:ident <- $s:expr) => {
		$crate::unsafe_as_str($crate::obfbytes!($buf <- ::core::convert::identity::<&str>($s).as_bytes()))
	};
	($s:expr) => {
		$crate::unsafe_as_str($crate::obfbytes!(::core::convert::identity::<&str>($s).as_bytes()))
	};
}
```

We can see, that under the hood, `obfbytes!` seems to be doing the work. This is defined in 
the `bytes.rs` file of the crate. 

```rust
/// Compiletime byte string obfuscation.
#[macro_export]
macro_rules! obfbytes {
    ($(let $name:ident = $s:expr;)*) => {
        $(let ref $name = $crate::__obfbytes!($s);)*
    };
    ($name:ident = $s:expr) => {{
        $name = $crate::__obfbytes!($s);
        &$name
    }};
    ($buf:ident <- $s:expr) => {{
        let buf = &mut $buf[..$s.len()];
        buf.copy_from_slice(&$crate::__obfbytes!($s));
        buf
    }};
    ($s:expr) => {
        &$crate::__obfbytes!($s)
    };
```

Again, we have some indirection, leading us to `__obfbytes!` (I added some comments):

```rust
#[doc(hidden)]
#[macro_export]
macro_rules! __obfbytes {
    ($s:expr) => {{
        use ::core::primitive::*;

        // [TAG#0]
        const _OBFBYTES_STRING: &[u8] = $s; 
        const _OBFBYTES_LEN: usize = _OBFBYTES_STRING.len();

        // [TAG#1]
        const _OBFBYTES_KEYSTREAM: [u8; _OBFBYTES_LEN] = $crate::bytes::keystream::<_OBFBYTES_LEN>($crate::random!(u32, "key", stringify!($s)));

        // [TAG#2]
        static _OBFBYTES_SDATA: [u8; _OBFBYTES_LEN] = $crate::bytes::obfuscate::<_OBFBYTES_LEN>(_OBFBYTES_STRING, &_OBFBYTES_KEYSTREAM);
        
        // [TAG#3]
        $crate::bytes::deobfuscate::<_OBFBYTES_LEN>(
            $crate::xref::xref::<_,  // [TAG#4]
                {$crate::random!(u32, "offset", stringify!($s))},
                {$crate::random!(u64, "xref", stringify!($s))}>
                (&_OBFBYTES_SDATA),
            &_OBFBYTES_KEYSTREAM)
    }};
}
```

Now we're talking! This is it, we made it to the bottom. Best to break this down into chunks:

- `[TAG#0]` get a byte slice of the string's data and the length
- `[TAG#1]` generate a key stream (uses xorshift for randoms)
- `[TAG#2]` do the obfuscation
- `[TAG#3]` ... and the deobfuscation
- `[TAG#4] xref? does this mean xrefs are obfuscated as well?

This is the keystream generation, showing us that for each string byte, there is one key byte.

```rust
#[inline(always)] 
pub const fn keystream<const LEN: usize>(key: u32) -> [u8; LEN] {
    let mut keys = [0u8; LEN]; 
    let mut round_key = key;
    let mut i = 0;
    // Calculate the key stream in chunks of 4 bytes
    while i < LEN & !3 {
        round_key = next_round(round_key);
        let kb = round_key.to_ne_bytes();
        keys[i + 0] = kb[0];
        keys[i + 1] = kb[1];
        keys[i + 2] = kb[2];
        keys[i + 3] = kb[3];
        i += 4;
    }
    // Calculate the remaining bytes of the key stream
    round_key = next_round(round_key);
    let kb = round_key.to_ne_bytes();
    match LEN % 4 {
        1 => {
            keys[i + 0] = kb[0];
        },
        2 => {
            keys[i + 0] = kb[0];
            keys[i + 1] = kb[1];
        },
        3 => {
            keys[i + 0] = kb[0];
            keys[i + 1] = kb[1];
            keys[i + 2] = kb[2];
        },
        _ => (),
    }
    return keys;
}
```

The obfuscation itself looks like this, no surprise there, each data byte is XOR'd
with one key byte.

```rust
/// Obfuscates the input string and given key stream.
#[inline(always)]
pub const fn obfuscate<const LEN: usize>(s: &[u8], k: &[u8; LEN]) -> [u8; LEN] {
    if s.len() != LEN {
        panic!("input string len not equal to key stream len");
    }
    let mut data = [0u8; LEN];
    let mut i = 0usize;
    while i < LEN {
        data[i] = s[i] ^ k[i];
        i += 1;
    }
    return data;
}
```

So as you can see, the obfuscation part itself, regarding the string's bytes, is nothing out
of the ordinary. What I find interesting is the `xref` thing. 

## Into xref

We already saw the deobfuscation above, but I'll put it here again, just so we have a reference.

```rust
$crate::bytes::deobfuscate::<_OBFBYTES_LEN>(
    $crate::xref::xref::<_, // <-- xref
        {$crate::random!(u32, "offset", stringify!($s))},
        {$crate::random!(u64, "xref", stringify!($s))}>
        (&_OBFBYTES_SDATA),
        &_OBFBYTES_KEYSTREAM
)
```

And the internals, with the obfuscation function.

```rust
/// Obfuscates the xref to data reference.
#[inline(always)]
pub fn xref<T: ?Sized, const OFFSET: u32, const SEED: u64>(p: &'static T) -> &'static T {
    unsafe {
        let mut p: *const T = p;
        // Launder the values through black_box to prevent LLVM from optimizing away the obfuscation
        let val = inner::<SEED>(hint::black_box((p as *const u8).wrapping_sub(obfuscate::<SEED>(OFFSET))), hint::black_box(OFFSET));
        // set_ptr_value
        *(&mut p as *mut *const T as *mut *const u8) = val;
        &*p
    }
}

const fn obfuscate<const SEED: u64>(mut v: u32) -> usize {
    let mut seed = SEED;
    use crate::splitmix;
    seed = splitmix(seed);
    v = obfchoice(v, seed);
    seed = splitmix(seed);
    v = obfchoice(v, seed);
    seed = splitmix(seed);
    v = obfchoice(v, seed);
    seed = splitmix(seed);
    v = obfchoice(v, seed);
    seed = splitmix(seed);
    v = obfchoice(v, seed);
    return (v & 0xffff) as usize
}

#[inline(always)]
const fn obfchoice(v: u32, seed: u64) -> u32 {
    let rand = (seed >> 32) as u32;
    match seed & 7 {
        0 => v.wrapping_add(rand),
        1 => rand.wrapping_sub(v),
        2 => v ^ rand,
        3 => v ^ v.rotate_left(non_zero(rand & 7)),
        4 => !v,
        5 => v ^ (v >> non_zero(rand & 31)),
        6 => v.wrapping_mul(non_zero(rand)),
        7 => v.wrapping_neg(),
        _ => unsafe { hint::unreachable_unchecked() }
    }
}
```

So, in the most simple terms, what this does is add some offset to a data reference, effectively obfuscating it. 
Now, we have all of the parts we need for reverse engineering.

## Reverse Engineering - Release Binary

We'll do the release binary first. I already showed you how to find `main` above. Here, I will use the decompiler
mixed in with the disassembly. Here's the first part of the `main`:

```c
// 0x1400010a3
local_48 = 0xfffffffffffffffe;
local_78 = (undefined **)0x178a5f3f5;

// [TAG#1]
puVar6 = (ulonglong *)FUN_140001070(0x14000f196,0x78a5f3f5);

// [TAG#2]
local_b0 = *puVar6 ^ 0x1b4949e8087daa71;
local_a8 = (uint)puVar6[1] ^ 0x7cfe4a92;

local_90 = &local_b0;
local_88 = 0xc;
local_98 = &LAB_140001030;
local_78 = &PTR_s_loading_library:_1400193e0;
local_70 = 2;
local_58 = 0;
local_60 = 1;
local_a0 = &local_90;
local_68 = &local_a0;
FUN_140004a30((longlong *)&local_78);
```

First, `[TAG#1]` -  `puVar6 = (ulonglong *)FUN_140001070(0x14000f196,0x78a5f3f5);`

Inside we find some arithmetic, which is then applied to the first argument. Possibly,
this is our xref obfuscation:

```c
longlong FUN_140001070(longlong param_1,uint param_2)
{
  uint uVar1;
  uint uVar2;
  
  uVar1 = (param_2 << 4 | param_2 >> 0x1c) ^ param_2;
  uVar2 = uVar1 * -0x6374cddd; // 0x9C8B3223 (unsigned hex)
  return (ulonglong)(((uVar1 * 0x39166446 | (uint)((int)uVar2 < 0)) ^ uVar2) & 0xffff) + param_1;
}
```

Doing the math shows us that:

```
uVar1         =     0xf2facca2
uVar2         =     0x08379e26
FUN_140001070 =     0x140019400
```

The return address leads to a valid memory location, here's the data:

```c
uint8_t data_140019400[] = { 
    0x1a, 0xcf, 0x0f, 0x66, 0x8d, 0x25, 0x7a, 
    0x29, 0xbc, 0x2e, 0x92, 0x10, 0x4b, 0x72, 
    0x06, 0xc1, 0xc2, 0xee, 0x5a, 0xf6, 0xcf, 
    0x02, 0x3b, 0xa6, 0x86, 0x08, 0xd5, 0x14, 
    0x05, 0x1a, 0x1d, 0x2f, 0xfa, 0x00, 
};
```

That means we indeed found the deobfuscation of our xref. Next, the deobfuscation
of the string itself happens at `[TAG#2]`.

Let's apply the code there to our data using this crappy piece of C-code:

```c
void
deob(void)
{
    uint32_t i = 0;

    uint8_t data_140019400[] = {
        0x1a, 0xcf, 0x0f, 0x66, 0x8d, 0x25, 0x7a,
        0x29, 0xbc, 0x2e, 0x92, 0x10, 0x4b, 0x72,
        0x06, 0xc1, 0xc2, 0xee, 0x5a, 0xf6, 0xcf,
        0x02, 0x3b, 0xa6, 0x86, 0x08, 0xd5, 0x14,
        0x05, 0x1a, 0x1d, 0x2f, 0xfa, 0x00,
    };

    uint64_t *p = (uint64_t*)&data_140019400[0];
    uint64_t key0 = 0x1b4949e8087daa71;
    uint64_t key1 = 0x7cfe4a92;

    *p ^= key0;
    p++;
    *p ^= key1;

    for(i = 0; i < sizeof(data_140019400); i++)
    {
        printf("%c ", data_140019400[i]);
    }

    printf("\n");
}
```

It actually spews out the string and of course the rest of the data
at the address `0x140019400`, which is non-ASCII.

```
kernel32.dll
```

So, using this knowledge, we know how to get our first string back, which
is actually a `&str`.

The next string is first deobfuscated, then converted to a `String` type.
Let's see how this goes. The xref obfuscation is chosen randomly, thus we
will get a different function for deobfuscation. What remains the same is
that the function receives two parameters, each of them a scalar/immediate
value. Here's a part of the decompiler output:

```c
--- SNIP ---
  // [TAG#0]
  v_str_data = (ulonglong *)FUN_140001050(0x14000afce,0xdab53045);
  uVar2 = *v_str_data;
  uVar3 = v_str_data[1];
  uVar5 = v_str_data[2];
  bVar1 = *(byte *)((longlong)v_str_data + 0x14);
  // [TAG#1]
  local_80 = (ulonglong *)thunk_FUN_140007940(0x15,1);
  if (local_80 != (ulonglong *)0x0) {
    uVar6 = (uint)uVar5 ^ 0x1f2d223f;
    // [TAG#2]
    *local_80 = uVar2 ^ 0xc775c1f8b1720623;
    local_80[1] = uVar3 ^ 0x25fb38a8961535fd;
    *(char *)(local_80 + 2) = (char)uVar6;
    *(char *)((longlong)local_80 + 0x13) = (char)(uVar6 >> 0x18);
    *(short *)((longlong)local_80 + 0x11) = (short)(uVar6 >> 8);
    // [TAG#3]
    *(byte *)((longlong)local_80 + 0x14) = bVar1 ^ 0xca;
--- SNIP ---
```

I did a markup of what I assume is the obfuscated string's data bytes,
renaming the variable to `v_str_data`. Notice that we can look for 
anything that is XOR'ed and trace that back, meaning here, we can see
that `uVar5`, `uVar2` etc. (`[TAG#2]`) are good candidates for tracing upwards.
We can see that these are part of `v_str_data`, which is in turn set by
the call `FUN_140001050(0x14000afce,0xdab53045)` (`[TAG#0]`). For this 
string the function is:

```c
longlong FUN_140001050(longlong param_1,uint param_2)
{
  uint uVar1;
  
  uVar1 = (param_2 ^ 0xef71934d) * 0x30a35c11;
  return (ulonglong)((uVar1 >> 0xb ^ uVar1) & 0xffff) + param_1;
}
```

Again, we can just write a small C program, but notice that the last
byte of the string is deobfuscated further below (`[TAG#3]`). This is
probably a small optimization, if you can even call it that. First,
we get some memory for the resulting `String` (`[TAG#1]`, `local_80`). 
Then the deobfuscation of all bytes except the last happens, with the last
byte deobfuscated when the data is moved into the `String`. Here's our
deobfuscation:

```
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// string data from deobfuscated location
uint8_t carr[] = { 
    0x4b, 0x72, 0x06, 0xc1, 0xc2, 0xee, 0x5a, 0xf6, 
    0xcf, 0x02, 0x3b, 0xa6, 0x86, 0x08, 0xd5, 0x14, 
    0x05, 0x1a, 0x1d, 0x2f, 0xfa, 0x00 
};

// xref deobfuscation
uint64_t 
FUN_140001050(uint64_t param_1, uint32_t param_2)
{
  uint32_t temp = (param_2 ^ 0xef71934d) * 0x30a35c11;
  return (uint64_t)((temp >> 0xb ^ temp) & 0xffff) + param_1;
}

int
main(void)
{
    uint64_t *ptr = NULL;
    uint64_t location = FUN_140001050(0x14000afce,0xdab53045);
    printf("location: %016lx\n", location);
    ptr = (uint64_t*)&carr[0];
    *ptr ^= 0xc775c1f8b1720623;
    ++ptr;
    *ptr ^= 0x25fb38a8961535fd;
    ++ptr;
    *ptr ^= 0x1f2d223f;
    // last byte
    carr[sizeof(carr)-2] ^= 0xca;
    printf("%s\n", carr);

    return 0;
}
```

Now, we have our string back: `http://127.0.0.1:8000`.

## Takeaways

For the release version, things actually look pretty much straightforward.
We might even have some ideas to use emulation the deobfuscated in an automated
way. Let's continue with the debug build version.

# Debug Binary

Well, this is... painful. I you open the debug version with a disassembler, 
it's rather straightforward to find the main function at `0x140004a10`. 
Inside this function things look really complicated. Let's break down the
xref deobfuscation first. This happens at these lines:

```
// 0x140005924
v_0x140016bcf = FUN_1400028a0(0x140016bcf);
v_0x78a5f3f5 = FUN_140002880(0x78a5f3f5);
v_str_location = FUN_140003910(v_0x140016bcf,v_0x78a5f3f5);
```

The functions `FUN_1400028a0` and `FUN_140002880` just return the
value that was passed to them, the deobfuscation happens in `FUN_140003910`.
With this, we get the string location, it's at `0x0140020e39`.

The next part is more complex. To decipher it's workings, I added some variable
names, everything added by me is prefixed with `v_` or `g_`. Let's have a look:

```c
// 0x140005979
  memset(&v_result_store,0,0xc);
  v_i = 0;
  local_438 = 0xc;
  local_450 = &v_result_store;
  local_448 = 0xc;
  local_4e0 = &v_result_store;
  local_4e8 = v_str_location;
  local_440 = v_str_location;
LAB_1400059df:
  v_i0 = v_i;
  if (7 < v_i) {
    do {
      v_i0 = v_i;
      if (0xb < v_i) goto LAB_14000629e;
      local_458 = v_i;
      local_460 = v_str_location;
      FUN_140008030(v_str_location,v_i,1);
      // [TAG#0]
      v_cur = FUN_140001990((undefined4 *)(v_str_location + v_i0));
      local_504 = v_cur;
      local_4d8 = v_cur;
      local_4d4 = v_cur;
      v_cur0 = FUN_140002270(v_cur);
      // [TAG#1]
      if (v_i < 0xc) {
        v_byte0 = (&g_XORKEY)[v_i];
        v_i+1 = v_i + 1;
        if (v_i != 0xffffffffffffffff) goto LAB_140005c1d;
        FUN_14001fe50(&PTR_s_C:\Users\user\.cargo\registry\sr_140020b68);
LAB_140005c38:
        // [TAG#2]
        v_byte1 = (&g_XORKEY)[v_i+1];
        v_i+2 = v_i + 2;
        if (v_i < 0xfffffffffffffffe) goto LAB_140005c80;
        FUN_14001fe50(&PTR_s_C:\Users\user\.cargo\registry\sr_140020b98);
LAB_140005c9b:
        v_byte2 = (&g_XORKEY)[v_i+2];
        v_i+3 = v_i + 3;
        if (v_i < 0xfffffffffffffffd) goto LAB_140005ce3;
        FUN_14001fe50(&PTR_s_C:\Users\user\.cargo\registry\sr_140020bc8);
LAB_140005d01:
        // [TAG#3]
        v_xorkey_i = CONCAT13((&g_XORKEY)[v_i+3],CONCAT12(v_byte2,CONCAT11(v_byte1,v_byte0)));
        local_4d0 = v_xorkey_i;
        v_xor = FUN_140002270(v_xorkey_i);
        v_i0 = v_i;
        local_480 = &v_result_store;
        local_478 = v_i;
        v_deobfuscated_i = v_cur0 ^ v_xor;
        FUN_140007d50((ulonglong)&v_result_store,v_i,1);
        // [TAG#4]
        v_deobfuscated_i0 = FUN_140002260(v_cur0 ^ v_xor);
        local_4c8 = v_deobfuscated_i0;
        local_4c4 = v_deobfuscated_i0;
        // [TAG#5]
        FUN_140001a50((undefined4 *)((longlong)&v_result_store + v_i0),v_deobfuscated_i0);
        v_next_i = v_i + 4;
        if (0xfffffffffffffffb < v_i) goto LAB_140005e38;
      }
      else {
        FUN_14001fa44(v_i,0xc,&PTR_s_C:\Users\user\.cargo\registry\sr_140020b50);
LAB_140005c1d:
        if (v_i+1 < 0xc) goto LAB_140005c38;
        FUN_14001fa44(v_i+1,0xc,&PTR_s_C:\Users\user\.cargo\registry\sr_140020b80);
LAB_140005c80:
        if (v_i+2 < 0xc) goto LAB_140005c9b;
        FUN_14001fa44(v_i+2,0xc,&PTR_s_C:\Users\user\.cargo\registry\sr_140020bb0);
LAB_140005ce3:
        if (v_i+3 < 0xc) goto LAB_140005d01;
        FUN_14001fa44(v_i+3,0xc,&PTR_s_C:\Users\user\.cargo\registry\sr_140020be0);
      }
      v_i = v_next_i;
    } while( true );
  }
```

This looks pretty complicated, but we can get an orientation by looking at the do-while
loop. Here, we have an index that is incremented: `v_i`. 

The function at `[TAG#0]` returns the current offset into the obfuscated string's location.
Note that it's returned as a 32-bit integer. Note that the function `FUN_140001990` does
a check on the pointer passed to it, then dereferences. This is, with high likelyhood a 
check if a read access to the pointer passed in will violate any constraints or
permissions. We can see this inside the function:

```c
undefined4 FUN_140001990(undefined4 *param_1)
{
  // check out this call
  FUN_140002740((ulonglong)param_1,1); // <-- pointer check
  return *param_1;
}

/* inside: FUN_140002740
    FUN_14001fa00("unsafe precondition(s) violated: ptr::read_volatile requires that the 
    pointer arg ument is aligned and non-nullC:\\Users\\user\\.rustup\\toolchains\\stable-x86_64-pc-windows-msvc 
    \\lib/rustlib/src/rust\\library\\core\\src\\ptr\\const_ptr.rs"
                  ,0x6e);
*/
```

So, now we know that `v_cur` points to the current 32-bit integer part of the array we want to deobfuscate. 
The next part at `[TAG#1]` concerns the XOR key used for deobfuscation. Here, we get 4 bytes from the XOR
key, for example the second byte at `[TAG#2]` and concatenate these to a 32-bit integer at `[TAG#3]`.
The actual XOR deobfuscation happens at `[TAG#4]`, the result is stored at `[TAG#5]`. Note that the storage
location is the buffer that is `memset` at the start of the listing.

All of the functions inbetween and the functions that receive the variables we are using as arguments are
only there to check if indices stay inside bounds, pointers are valid etc. Again, as in the first post of
my Rust series, we can see that the Debug build complicates reverse engineering through these checks.

Let's reconstruct this in small C program:

```
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint8_t g_DATA[] = { 0x1a, 0xcf, 0x0f, 0x66, 0x8d, 0x25, 0x7a, 0x29, 0xbc, 0x2e, 0x92, 0x10 };
uint8_t g_KEY[]  = { 0x71, 0xaa, 0x7d, 0x08, 0xe8, 0x49, 0x49, 0x1b, 0x92, 0x4a, 0xfe, 0x7c };

int
main(void)
{
    uint8_t i = 0;
    uint32_t *key = 0;
    uint32_t *data = 0;

    key  = (uint32_t*)&g_KEY[0];
    data = (uint32_t*)&g_DATA[0];

    for(i = 0; i < 0xc; i += 4)
    {
        *data ^= *key;
        data++; key++;
    }

    printf("%s (%ld)\n", g_DATA, sizeof(g_DATA));

    return 0;
}
```

Not much going on here. I copied the data at the deobfuscated cross reference location, then added
the data from the pointer to the XOR key. The deobfuscation process is rather simple. Seen in a C
program, the control flow looks much simpler than in the decompiled rust program, again, because
the various (sanity) checks are not included.

The deobfuscation of the second string is pretty much the same as for the first you can see above.
Thus, I will omit this here.

# Conclusion

The xref obfuscation was something I haven't seen before, but deciphering what it does was manageable.
In hindsight, it was easier using the disassembled code than actually reading through the `obfstr` 
source code (at least for the Release build). As in the post before, we are clearly able to see that
the Debug build adds a lot of complexity. This makes it harder to reverse engineer than the Release
build. 

# Thanks and Mentions

The idea for this post came from `@cxiao`, without you, this writeup wouldn't exist, so thank you :)



