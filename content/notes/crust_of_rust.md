---
title: "Crust of Rust - Notes"
date: 2024-01-13T13:26:53+01:00
draft: false
---

These are my notes for Crust of Rust: 
https://www.youtube.com/playlist?list=PLqbS7AVVErFiWDOAVrPt7aYmnuuOLYvOa

---

- [x] [Memory Ordering and Atomics](#memoryorderingandatomics)
- [x] [Lifetimes](#lifetimes)
- [x] [SmartPointers and Interior Mutability](#smarts)


# Memory Ordering and Atomics
<a name="memoryorderingandatomics"></a>

Why do we need atomics?

- shared access to a memory value needs additional information in order for threads to synchronize and fix what guarantees are in place
- thread-safety: data races and undefined behavior is mitigated
- having an extra API has the added benefit of highlighting that we are issuing different instructions to the CPU: `bool <-> AtomicBool`

Memory Model

... Rust does not have a defined memory model => this is not that good for atomics etc, but no problem because we use LLVM and follow the C memory model.

-> we can follow the C++ memory model specification, this is very readable.

Sharing `atomics` between threads

1. leak a `Box`
2. use an `Arc`

---

`AtomicUsize` - same memory representation as a `usize`, but with a different set of methods. You can never access the value directly.

You can't share the `Atomic` value between threads, they are placed on the stack, so you have to use the heap (`Box` or `Arc` it). 

The methods of `AtomicUsize` use shared references to self, with which you can manipulate the value. For a normal usize, you can't have that.

`load` - takes the value in the `AtomicUsize` and returns a `usize`
`store` - takes a `usize`, stores it in the `AtomicUsize`

These methods want an `Ordering`. An Ordering tells the compiler which set of guarantees which you expect for this particular memory access.

`fetch_add` will atomically add, there are also a lot of other atomic methods in `AtomicUsize`.

---

Building a Mutex

An error when implementing a Mutex.
```rust
/// a spinlock, which we shouldn't use, as spinlocks are bad in general
/// there's an error in here.
pub fn with_lock<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
	while self.locked.load(Ordering::Relaxed) != UNLOCKED {}
	// ERROR: inbetween the load and the store, maybe another
	//        thread runs here.
	self.locked.store(LOCKED, Ordering::Relaxed);
	// SAFETY: we hold the lock, thus we can create a mutable
	// reference.
	let ret = f(unsafe {
		&mut *self.v.get()
	}); 
	self.locked.store(UNLOCKED, Ordering::Relaxed);
	ret
}
```

We fix this with `compare_exchange`. The race is between `load` and `store`, so we avoid the race with an atomic `compare_exchange`.

```rust
/// takes a function that it calls as soon as it has the lock
pub fn with_lock<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
	while self.locked.compare_exchange(
		UNLOCKED, // what the current should be for us to update it
		LOCKED,  // what it should be set to, if it is what the first arg was
		Ordering::Relaxed, 
		Ordering::Relaxed).is_err() {}
	// SAFETY: we hold the lock, thus we can create a mutable
	// reference.
	let ret = f(unsafe {
		&mut *self.v.get()
	}); 
	self.locked.store(UNLOCKED, Ordering::Relaxed);
	ret
}
```

If all CPUs spin are trying to get the lock via `compare_exchange` (get exclusive access to the boolean), the cores have to cooperate (expensive) to check the value each time - this is expensive.

Check out the **MESI protocol** - this explains well why this is expensive.

Often spinlocks do this:

```
while COMPARE_EXCHANGE(...) { <- if we failed to get the lock, do LOAD
	while LOAD(...) // <- read only, so more efficient
}
```

`compare_exchange_weak` - difference is `compare_exchange` is only allowed to fail if the `current` value you pass in does not match the current value of the variable. `compare_exchange_weak` is allowed to fail spuriously. Even if the `current` value matches the current value of the variable.

Why do we have this? 

- x86 implements a `compare-and-swap` instruction
- on ARM: `LDREX` and `STREX` (load and store exclusive) STREX will only store if exclusive access to the memory location is still held, if not the instruction will fail. 

That's why we need `compare_exchange_weak`. On ARM `compare_exchange` is implemented using a loop of LDREX and STREX. (this is more efficient than one instruction for `compare-and-swap` in some cases). `compare_exchange_weak` is `LDREX, STREX` - if you're not calling `compare_exchange` in a loop, use `compare_exchange_weak`.

---

Ordering

This is our current function

```rust
/// takes a function that it calls as soon as it has the lock
pub fn with_lock<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
	while self.locked.compare_exchange_weak(
		UNLOCKED, // what the current should be for us to update it
		LOCKED,  // what it should be set to, if it is what the first arg was
		Ordering::Relaxed, 
		Ordering::Relaxed).is_err() {
			// only read, no compare and exchange
			while self.locked.load(Ordering::Relaxed) == LOCKED {
				thread::yield_now();
			}
			thread::yield_now();
		}
	// SAFETY: we hold the lock, thus we can create a mutable
	// reference.
	let ret = f(unsafe {
		&mut *self.v.get()
	}); 
	self.locked.store(UNLOCKED, Ordering::Relaxed);
	ret
}
```

At this point nothing fails. But there is still a problem. The reason is the `Ordering`.

An `Ordering` is an allowed behavior. `Relaxed` means there are pretty much no guarantees, other than that the operation is atomic. 

```rust
#[test]
fn too_relaxed() {
	let x: &'static _ = Box::leak(Box::new(AtomicUsize::new(0)));
	let y: &'static _ = Box::leak(Box::new(AtomicUsize::new(0)));

	let t1 = spawn(move || {
		// read y, store to x
		let r1 = y.load(Ordering::Relaxed);
		x.store(r1, Ordering::Relaxed);
		r1
	});

	let t2 = spawn(move || {
		// read x, store to y
		let r2 = x.load(Ordering::Relaxed);
		y.store(42, Ordering::Relaxed);
		r2
	});

	let r1 = t1.join().unwrap();
	let r2 = t2.join().unwrap();
	// it is possible that r1 == r2 == 42
	// even though the store of 42 happens after r2 is read
}
```

This is surprising, `r2` should hold the value of `x` and is set before `y` is set to 42. `Relaxed` gives no guarantees about what values a thread can read from something another thread wrote.

The load of `x` in `let r2 = x.load(Ordering::Relaxed);` can see any value of `x`, which includes 42.

The modification order...

```
MO(x): 0 42 <-- modification order for x
MO(y): 0 42
```

... here means that any value from the set (0,42) can be chosen for x.
(The compiler can choose what to do first - there is no sequencing happening in the code after all, one thing does not have to happen after the other).

This makes safe locks impossible. Imagine the lock being activated after the lock should have already taken place - in that case, there is no lock.

---

Acquire/Release Memory Ordering

These memory orderings are used for shared resources. 

```rust
// this is correct, work with the value v, then release the lock
let ret = f(unsafe { &mut *self.v.get() });
self.locked.store(UNLOCKED, Ordering::Relaxed);
// with relaxed, this can happen, we unlock, then work with the value
self.locked.store(UNLOCKED, Ordering::Relaxed);
let ret = f(unsafe { &mut *self.v.get() });

// we fix this with Release memory ordering
let ret = f(unsafe { &mut *self.v.get() }); 
self.locked.store(UNLOCKED, Ordering::Release);
```

We need to couple this with `Acquire` - see docs.

```rust
while self.locked.compare_exchange_weak(
	UNLOCKED, // what the current should be for us to update it
	LOCKED,  // what it should be set to, if it is what the first arg was
	Ordering::Acquire, 
	Ordering::Relaxed).is_err() 
	{
		// only read, no compare and exchange
		while self.locked.load(Ordering::Relaxed) == LOCKED {
			thread::yield_now();
		}
		thread::yield_now();
	}
```

`AcqRel` - this is used for operations that do a read and a write, like compare exchange, this says "do the load with acquire semantics and the store with release semantics". This is used when you do a `fetch_add` or similar - when you have single operations.

---
#### fetch Operations

`fetch` operations are gentler variants of `compare_and_exchange` - instead of saying what the new value should be, tell the CPU how to compute the new value. in `compare_and_exchange` the current value is checked, if it is not the expected value, it will fail. `fetch_add` will not, it will tell you what the value was and the add to to, but not check the value beforehand.

---

#### SeqCst

see video explanation + code, it's a better walkthrough that could ever be done here in text.

It comes down to this:

- acquire and release impose an order on loads and stores
- when multiple of these orderings are applied to variables used in context, things get confusing
- for example: say x is loaded, acquire imposes an order, but x has multiple previous values. this can load to problems, which value is chosen? => we need a clear ordering here, that is `SeqCst`

All memory orderings impose a "what happens before" relationship for things happening concurrently.

----
#### loom

is a rust thread sanitizer - a strategy for taking a concurrent program, instrumenting it and testing it. This feeds you back *possible legal values* - as loom executes, it will run all possible thread interleavings, all possible memory orderings. 

---
#### atomic fences - Memory Barriers

there is a `fence` in the atomic module in the standard library. You can also pass a constant between threads - other than leaking a box or using an Arc.

`fence` is an atomic operation, that establishes a happens before relationship between two threads, but does not talk about a specific memory location. So, not like `load` and `store` with `Acquire`. A `fence` says: Synchronize with all other threads that do a `fence`.

See the C++ reference above for this.

---
#### volatile

`volatile` keyword is unrelated to `atomics`. There is a `std::ptr::read_volatile` and a write. 

---
#### AtomicPtr

... is not really special. The methods are specialized towards pointers, that's it.

---

# Lifetimes
<a name="lifetimes"> </a>

https://www.youtube.com/watch?v=rAl-9HwD858&list=PLqbS7AVVErFiWDOAVrPt7aYmnuuOLYvOa

Anonymous Lifetimes: places where you tell the compiler to *guess* the lifetime
```rust
impl Foo {
	/// compiler can guess the lifetime of the str, as the only other lifetime is to &self, 
	/// so str lives as long as self lives.
	fn get_ref(&self) -> &'_ str {}
}

/// using anonymous lifetimes to simplify
fn foo(x: &'a str, y: &'b str) -> &'a str {}
/// in the return value, the anonymous lifetime means "infer the lifetime"
fn foo(x: &str, y: &'_ str) -> &'_ str {}
```

Named Lifetimes: you tell the compiler what the lifetimes are `<'a>`
Special Lifetimes: `'static` - lives as long as the program

Error Message: `lifetime of reference outlives lifetime of borrowed content`

This means that `haystack`'s lifetime is not the same as `remainder`'s lifetime. Same goes for delimiter. What this tells us is the following:

- at the moment `new` is called, haystack or delimiter could be de-allocated
- if that happens, the references of remainder and delimiter are not valid anymore, but StrSplit still exists with these references!
- we need to specify a lifetime for haystack and delimiter in order to construct a relationship between the pointers we pass in and the pointers inside the struct

The fix is easy: Tell Rust that the internal references live as long as the external ones:

```rust
impl <'a> StrSplit<'a> {
    pub fn new(haystack: &'a str, delimiter: &'a str) -> Self {
        Self {
            remainder: haystack,
            delimiter
        }
    }
}
```

That means *haystack and delimiter live at least as a long is the internal remainder and delimiter*.

Why are there TWO `<'a>`? Same reason as for below:

```rust
struct Foo<T>;
// this is wrong, the compiler says: "you're using a type T here, but I don't know that type"
impl Foo<T> {}
// this tells the compiler that the impl block is generic over T
impl <T> Foo<T> {}
```

What is the `ref mut` here?

```rust
fn next(&mut self) -> Option<Self::Item> {

	if let Some(ref mut remainder) = self.remainder {
		// if there is some delimiter in the remainder
		if let Some(next_delim) = remainder.find(self.delimiter) {
			// 
			let until_delim = &remainder[..next_delim];
			*remainder = &remainder[(next_delim + self.delimiter.len())..];
			return Some(until_delim);
		} else {
			self.remainder.take()
		}
	} else {
		None
	}
}
```

- `ref mut` says: if `self.remainder` is some, do not move the value out of `self.remainder`, give me a mutable reference to the value inside of it
- with no `ref mut`: the value moves out of `self.remainder`

What does `take()` do?

```
impl <T> Option<T> {
	/// if the option is None, it returns None
	/// if it is Some, it returns the Option and sets the Option inside to None
	fn take(&mut self) -> Option<T>
}
```

Error: `returns a value referencing data owned by current function`

The problem is in the `format!("{}", c)`:
- this is the `delimiter` argument to `StrSplit::new`
- currently, this argument has the same lifetime as the `haystack` 
- we are giving it something that does not have the same lifetime, namely `format!(...)`
- `format!(...)` has the shorter lifetime, as such it is seen as `<'a>`

We have two options:

- make `delimiter` a `String`
- introduce a second lifetime

Until now we have: 

```rust
// #![warn(missing_debug_implementations, missing_docs)]

#[derive(Debug)]
pub struct StrSplit<'a> {
    remainder: Option<&'a str>, // missing lifetime: must live as long as the haystack 
    delimiter: &'a str, // missing lifetime: lives as long as remainder
}

impl <'a> StrSplit<'a> {
    pub fn new(haystack: &'a str, delimiter: &'a str) -> Self {
        Self {
            remainder: Some(haystack),
            delimiter
        }
    }
}

impl <'a> Iterator for StrSplit<'a> {

    type Item = &'a str; // missing lifetime: lives as long as what it references

    fn next(&mut self) -> Option<Self::Item> {

        if let Some(ref mut remainder) = self.remainder {
            // if there is some delimiter in the remainder
            if let Some(next_delim) = remainder.find(self.delimiter) {
                let until_delim = &remainder[..next_delim];
                // need to dereference, because remainder is &mut &str, we need
                // the new remainder should be put where remainder is pointing to
                *remainder = &remainder[(next_delim + self.delimiter.len())..];
                return Some(until_delim);
            } else {
                self.remainder.take()
            }
        } else {
            None
        }
    }
        
}

/// ERROR: we'll not compile because of the lifetime problem here.
fn until_char(s: &str, c: char) -> &str {
    StrSplit::new(s, &format!("{}", c)).next()
        .expect("strsplit always gives at least one result")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let haystack = "a b c d e";
        let letters = StrSplit::new(haystack, " ");
        assert!(letters.eq(vec!["a", "b", "c", "d", "e"].into_iter()));
    }

    #[test]
    fn tail() {
        let haystack = "a b c d ";
        let letters = StrSplit::new(haystack, " ");
        assert!(letters.eq(vec!["a", "b", "c", "d", ""].into_iter()));
    }


    #[test]
    fn until_char_test() {
        assert_eq!(until_char("hello world", 'o'), "hell");
    }
}
```

---
## Multiple Lifetimes

Usually you do not need multiple lifetimes, it's very rare.

Here is the Fix with multiple lifetimes:
```rust
// #![warn(missing_debug_implementations, missing_docs)]

#[derive(Debug)]
pub struct StrSplit<'haystack, 'delimiter> {
    remainder: Option<&'haystack str>, // missing lifetime: must live as long as the haystack 
    delimiter: &'delimiter str, // missing lifetime: lives as long as remainder
}

impl <'haystack, 'delimiter> StrSplit<'haystack, 'delimiter> {
    pub fn new(haystack: &'haystack str, delimiter: &'delimiter str) -> Self {
        Self {
            remainder: Some(haystack),
            delimiter
        }
    }
}

impl <'haystack, 'delimiter> Iterator for StrSplit<'haystack, 'delimiter> {

    type Item = &'haystack str; // this is only tied to the lifetime of haystack

    fn next(&mut self) -> Option<Self::Item> {

        if let Some(ref mut remainder) = self.remainder {
            // if there is some delimiter in the remainder
            if let Some(next_delim) = remainder.find(self.delimiter) {
                let until_delim = &remainder[..next_delim];
                // need to dereference, because remainder is &mut &str, we need
                // the new remainder should be put where remainder is pointing to
                *remainder = &remainder[(next_delim + self.delimiter.len())..];
                return Some(until_delim);
            } else {
                self.remainder.take()
            }
        } else {
            None
        }
    }
        
}

fn until_char(s: &str, c: char) -> &str {
    StrSplit::new(s, &format!("{}", c)).next()
        .expect("strsplit always gives at least one result")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let haystack = "a b c d e";
        let letters = StrSplit::new(haystack, " ");
        assert!(letters.eq(vec!["a", "b", "c", "d", "e"].into_iter()));
    }

    #[test]
    fn tail() {
        let haystack = "a b c d ";
        let letters = StrSplit::new(haystack, " ");
        assert!(letters.eq(vec!["a", "b", "c", "d", ""].into_iter()));
    }


    #[test]
    fn until_char_test() {
        assert_eq!(until_char("hello world", 'o'), "hell");
    }
}
```

Getting rid of the allocation:

```rust
StrSplit::new(s, &format!("{}", c)).next()
// same as this:
let delim = format!("{}", c);    // <== this is an allocation
StrSplit::new(s, delim).next()
```

We make delimiter generic + add a trait to it. All we need to know from delimiter is where the next occurrence of the delimiter is.

```rust
// #![warn(missing_debug_implementations, missing_docs)]

#[derive(Debug)]
pub struct StrSplit<'haystack, D> {
    remainder: Option<&'haystack str>, // missing lifetime: must live as long as the haystack 
    delimiter: D,
}

impl <'haystack, D> StrSplit<'haystack, D> {
    pub fn new(haystack: &'haystack str, delimiter: D) -> Self {
        Self {
            remainder: Some(haystack),
            delimiter
        }
    }
}

pub trait Delimiter {
    fn find_next(&self, s: &str) -> Option<(usize, usize)>;
}

impl Delimiter for &str {
    fn find_next(&self, s: &str) -> Option<(usize, usize)> {
        s.find(self).map(|start| {
            (start, start + self.len())
        })
    }
}

impl Delimiter for char {
    fn find_next(&self, s: &str) -> Option<(usize, usize)> {
        s.char_indices()
            .find(|(_,c)| c == self)
            .map(|(start, _)| (start, start+1))
    }
}


impl <'haystack, D> Iterator for StrSplit<'haystack, D> 
where 
    D: Delimiter
{

    type Item = &'haystack str; // this is only tied to the lifetime of haystack

    fn next(&mut self) -> Option<Self::Item> {

        if let Some(ref mut remainder) = self.remainder {
            // if there is some delimiter in the remainder
            if let Some((delim_start, delim_end)) = self.delimiter.find_next(&remainder) {
                let until_delim = &remainder[..delim_start];
                // need to dereference, because remainder is &mut &str, we need
                // the new remainder should be put where remainder is pointing to
                *remainder = &remainder[delim_end..];
                return Some(until_delim);
            } else {
                self.remainder.take()
            }
        } else {
            None
        }
    }
        
}

pub fn until_char(s: &str, c: char) -> &str {
    // now we can just pass the char instead having to allocate
    StrSplit::new(s, c).next()
        .expect("strsplit always gives at least one result")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let haystack = "a b c d e";
        let letters = StrSplit::new(haystack, " ");
        assert!(letters.eq(vec!["a", "b", "c", "d", "e"].into_iter()));
    }

    #[test]
    fn tail() {
        let haystack = "a b c d ";
        let letters = StrSplit::new(haystack, " ");
        assert!(letters.eq(vec!["a", "b", "c", "d", ""].into_iter()));
    }


    #[test]
    fn until_char_test() {
        assert_eq!(until_char("hello world", 'o'), "hell");
    }
}

```

---

# Smart Pointers and Interior Mutability 
<a name="smarts"> </a>

The top level module is `std::cell`.

Sometimes you need multiple references to an object AND mutate it. The idea here is a type that looks immutable from the outside, but it has methods that allow you to mutate the internals.

---
`std::cell::Cell` - https://doc.rust-lang.org/std/cell/struct.Cell.html

In this example, you can see that `Cell<T>` enables mutation inside an immutable struct. In other words, it enables “interior mutability”.

```rust
use std::cell::Cell;

struct SomeStruct {
    regular_field: u8,
    special_field: Cell<u8>,
}

let my_struct = SomeStruct {
    regular_field: 0,
    special_field: Cell::new(1),
};

let new_value = 100;

// ERROR: `my_struct` is immutable
// my_struct.regular_field = new_value;

// WORKS: although `my_struct` is immutable, `special_field` is a `Cell`,
// which can always be mutated
my_struct.special_field.set(new_value);
assert_eq!(my_struct.special_field.get(), new_value);
```

Key Point: You can never get a pointer into the cell. Thus, there aren't multiple references to one thing, as such, mutating the thing inside is ok. Also, `cell` does not implement `Sync` - that means if you have a reference to a cell, you can never give that reference to a different thread. Thus, there can only one thread that has a reference to the cell.

The core of most of these "interior mutability" types is `std::cell::UnsafeCell`. You can use this to get raw pointers to the insides of things. You have to make sure that the unsafe access is indeed safe.

*The only way to go from a shared reference to an exclusive reference is by `std::cell::UnsafeCell` - we can't cast a shared to an exclusive reference. `UnsafeCell` is something that gives the compiler special information, in principle, `UnsafeCell<T>` is just a `T` *

Cell is used for smaller values, numbers, which need to be mutated from multiple different places. It's often used with thread-locals - for example for a thread-local state.

We could implement the setting of a value for cell like this:

```rust
pub fn set(&self, value: T) {
	// get() gives a raw exclusive pointer to the inner thing
	// dereference of a raw pointer is unsafe, which get() does.
	unsafe {
		*self.value.get() = value;
	}
}
```

But this is wrong, there is nothing that really prevents us from using the cell in additional threads.
Also, this can also go wrong with a single thread

```rust
let x = Cell::new(string::from("test"));
let first = x.get();
x.set(String::new());          // <-- the reference stored in first is now gone
x.set(String::from("world"));
println!("{first}")            // this prints "world", but not "test" the pointer we took out now points somewhere else!

// this is almost like a use-after-free - that is bad and can lead to undefined behavior
```

Now, the fixed, correct `Cell::get` never gives out the reference, but merely a copy:

```rust
pub fn get(&self) -> T 
	where 
		T: Copy 
{
	unsafe { *self.value.get() }
}
```

The full `Cell` with safety comments:

```rust
pub struct Cell<T> {
    value: UnsafeCell<T>,
}

impl<T> Cell<T> {

    pub fn new(value: T) -> Self {
        Cell { 
            value: UnsafeCell::new(value) 
        }
    }

    pub fn set(&self, value: T) {
        // get() gives a raw exclusive pointer to the inner thing
        // dereference of a raw pointer is unsafe, which get() does.
        // SAFETY: we know nobody else is concurrently mutating self.value because
        //         cell is !Sync (this is implied by UnsafeCell, which is !Sync)
        // SAFETY: we can never invalidate a reference, because we don't give
        //         one out
        unsafe {
            *self.value.get() = value;
        }
    }

    pub fn get(&self) -> T 
        where 
            T: Copy 
    {
        // SAFETY: we know nobody else is modifying this value, since only one
        //         thread can execute this (because of !Sync)
        unsafe { *self.value.get() }
    }
}
```

---

`RefCell` - https://doc.rust-lang.org/std/cell/struct.RefCell.html

*A mutable memory location with dynamically checked borrow rules*
Normally in Rust, borrow checking is done at compile time. RefCell lets you check at runtime if anyone else is mutating something (Trees, Graph Traversal). This is safe dynamic borrow checking.

A naive implementation:

```rust
use std::cell::UnsafeCell;

enum RefState {
    Unshared,
    Shared(usize),      // immutable
    Exclusive           // mutable
}

pub struct RefCell<T> {
    value: UnsafeCell<T>,
    state: RefState,
}

impl<T> RefCell<T> {

    pub fn new(value: T) -> Self {
        Self {
            value: UnsafeCell::new(value),
            state: RefState::Unshared,
        }
    }

    pub fn borrow(&self) -> Option<&T> {
        match self.state {
            // if we have not given out any references, we can give a shared one
            RefState::Unshared => {
                self.state = RefState::Shared(1);
                unsafe { &*self.value.get() }
            }
            // multiple shared references are ok as well
            RefState::Shared(n) => {
                self.state = RefState::Shared(n+1);
                unsafe { &*self.value.get() }
            }
            // if there's already a mutable refernce given out, we can't give
            // another one out.
            RefState::Exclusive => None,
        }
    }

    pub fn borrow_mut(&self) -> Option<&mut T> {
        if let RefState::Unshared = self.state {
            self.state = RefState::Exclusive;
            Some(unsafe { &mut *self.value.get() })
        } else {
            // if we have given out ANY reference, it's not ok to give out
            // a mutable reference.
            None
        }
    }

}
```

- this cannot be thread-safe, as the `RefState::Shared(n)` reference count is not thread-safe
- have a look at `borrow` and `borrow_mut` - this cannot work, we change the internal value `RefCell::state` but we have an immutable reference
- note that `RefCell` is `!Sync` - implied by `UnsafeCell`

This leaves us with:

- we don't need to be thread-safe, because we can't use this construct in threads anyway, as it's `!Sync`
- if we need interior mutability, we can just use `Cell` to fix our problem (`state: UnsafeCell => state: Cell::new(RefState))

This is the fixed code:

```rust
use std::cell::UnsafeCell;
use crate::cell::Cell;

#[derive(Copy, Clone)]
enum RefState {
    Unshared,
    Shared(usize),      // immutable
    Exclusive           // mutable
}

pub struct RefCell<T> {
    value: UnsafeCell<T>,
    state: Cell<RefState>,
}

impl<T> RefCell<T> {

    pub fn new(value: T) -> Self {
        Self {
            value: UnsafeCell::new(value),
            state: Cell::new(RefState::Unshared),
        }
    }

    pub fn borrow(&self) -> Option<&T> {

        match self.state.get() {
            // if we have not given out any references, we can give a shared one
            RefState::Unshared => {
                self.state.set(RefState::Shared(1));
                // SAFETY: there is only one reference that is immutable, there
                //         is no exclusive (mutable) reference
                Some(unsafe { &*self.value.get() })
            }
            // multiple shared references are ok as well
            RefState::Shared(n) => {
                self.state.set(RefState::Shared(n+1));
                // SAFETY: there are only references that are immutable, there
                //         is no exclusive (mutable) reference
                Some(unsafe { &*self.value.get() })
            }
            // if there's already a mutable refernce given out, we can't give
            // another one out.
            RefState::Exclusive => None,
        }
    }

    pub fn borrow_mut(&self) -> Option<&mut T> {
        if let RefState::Unshared = self.state.get() {
            self.state.set(RefState::Exclusive);
            // SAFETY: no other references have been given
            //         out or can be given out after this.
            Some(unsafe { &mut *self.value.get() })
        } else {
            // if we have given out ANY reference, it's not ok to give out
            // a mutable reference.
            None
        }
    }
}
```

New Problem: We never decrement the reference count, we need to track how many references there are currently and decrement if necessary, or even drop an exclusive reference.

```rust
use std::cell::UnsafeCell;
use crate::cell::Cell;

#[derive(Copy, Clone)]
enum RefState {
    Unshared,
    Shared(usize),      // immutable
    Exclusive           // mutable
}

pub struct RefCell<T> {
    value: UnsafeCell<T>,
    state: Cell<RefState>,
}

impl<T> RefCell<T> {

    pub fn new(value: T) -> Self {
        Self {
            value: UnsafeCell::new(value),
            state: Cell::new(RefState::Unshared),
        }
    }

    pub fn borrow(&self) -> Option<Ref<'_, T>> {

        match self.state.get() {
            // if we have not given out any references, we can give a shared one
            RefState::Unshared => {
                self.state.set(RefState::Shared(1));
                // SAFETY: there is only one reference that is immutable, there
                //         is no exclusive (mutable) reference
                Some(Ref { refcell: self })
            }
            // multiple shared references are ok as well
            RefState::Shared(n) => {
                self.state.set(RefState::Shared(n+1));
                // SAFETY: there are only references that are immutable, there
                //         is no exclusive (mutable) reference
                Some(Ref { refcell: self })
            }
            // if there's already a mutable refernce given out, we can't give
            // another one out.
            RefState::Exclusive => None,
        }
    }

    pub fn borrow_mut(&self) -> Option<RefMut<'_, T>> {
        if let RefState::Unshared = self.state.get() {
            self.state.set(RefState::Exclusive);
            // SAFETY: no other references have been given
            //         out or can be given out after this.
            Some(RefMut { refcell: self })
        } else {
            // if we have given out ANY reference, it's not ok to give out
            // a mutable reference.
            None
        }
    }

}

// we need this to be able to track the reference count
struct Ref<'refcell, T> {
    refcell: &'refcell RefCell<T>,
}
// this implements reference counting
impl<T> Drop for Ref<'_, T> {
    fn drop(&mut self) {
        match self.refcell.state.get() {
            // can't be shared if exclusive, so this is impossible
            RefState::Exclusive => unreachable!(),
            // to drop we need a ref in the first place, so impossible
            RefState::Unshared => unreachable!(),
            RefState::Shared(1) => {
                self.refcell.state.set(RefState::Unshared);
            },
            RefState::Shared(n) => {
                self.refcell.state.set(RefState::Shared(n-1));
            }
        }
    }
}

// if the user borrows, he doesn't want this weird Ref<'_, T> type, but the
// Option with the type in it so he can actually do something with it.
// we can implement this behavior with the Deref trait. This is invoked when you
// use the dot operator
impl<T> std::ops::Deref for Ref<'_, T> {

    type Target = T;

    // given a reference to self, give my a reference to the Target type
    // if you have a Ref of T, you can call any method that requires a Ref of T
    // on it. It dereferences into it, that means RefCell is now a smart pointer
    fn deref(&self) -> &Self::Target {
        // get the value inside the refcell
        // SAFETY: a Ref is only created if no exclusive references have been
        //         given out. Once it is given out, state is set to Shared, so
        //         no exclusive references are given out. So dereferencing into
        //         a shared reference is fine.
        unsafe { &*self.refcell.value.get() }
    }
}

struct RefMut<'refcell, T> {
    refcell: &'refcell RefCell<T>,
}

impl<T> Drop for RefMut<'_, T> {
    fn drop(&mut self) {
        match self.refcell.state.get() {
            // can't be shared if exclusive, so this is impossible
            RefState::Exclusive => self.refcell.state.set(RefState::Unshared),
            // to drop we need a ref in the first place, so impossible
            RefState::Unshared | RefState::Shared(_) => unreachable!(),
        }
    }
}

impl<T> std::ops::Deref for RefMut<'_, T> {

    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: see SAFETY DerefMut 
        unsafe { &*self.refcell.value.get() }
    }
}


impl<T> std::ops::DerefMut for RefMut<'_, T> {
    // SAFETY: A RefMut is only created, if no other references have been given
    //         out. Once given out, state is set to Exclusive, so no future
    //         references are given out. Lease on inner value is Exclusive.
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.refcell.value.get() }
    }
}
```

With this code, it is not possible to get two mutable references to an inner value.

---

`Rc` - Reference Counted Pointer to something on the Heap

From the Documentation: 
```
A single-threaded reference-counting pointer. ‘Rc’ stands for ‘Reference Counted’. The type Rc<T> provides shared ownership of a value of type T, allocated in the heap. Invoking clone on Rc produces a new pointer to the same allocation in the heap. When the last Rc pointer to a given allocation is destroyed, the value stored in that allocation (often referred to as “inner value”) is also dropped.

Shared references in Rust disallow mutation by default, and Rc is no exception: you cannot generally obtain a mutable reference to something inside an Rc. If you need mutability, put a Cell or RefCell inside the Rc; see an example of mutability inside an Rc.*
```

This means that if we need a mutable `Rc` we need to combine it with a `Cell` or a `RefCell`.

- `Rc` never provides mutability, it only provides counted references
- it deallocates when the last reference goes away
- `Rc` is `!Sync`

We have to fix the `drop`, see the comment in the code:

```rust
// we need to drop the box at some point
impl<T> Drop for Rc<T> {

    fn drop(&mut self) {
        let inner = unsafe { &*self.inner };
        let c = inner.refcount.get();
        if c == 1 {
            // SAFETY: we are the only reference and we should be dropped
            drop(inner);
            // we don't want to take a shared pointer and drop it, that's why
            // rust wants a *mut here, instead of *const.
            let _ = Box::from_raw(self.inner); // <-- this will fail to compile
            // to get around this, is to use std::ptr::NonNull;
            // this tells the compiler that a pointer cannot be NULL
        } else {
            // there are other Rc's so don't drop the Box
            inner.refcount.set(c-1);
        }
    }

}
```

The Fix: We use std::ptr::NonNull.

```rust
use crate::cell::Cell;
use std::ptr::NonNull;

pub struct RcInner<T> {
    value: T,
    refcount: Cell<usize>,
}

pub struct Rc<T> {
    inner: NonNull<RcInner<T>>,
    // we can't keep the reference count here, because of the clone
    // the reference count has to be in the value that is being cloned
}

impl<T> Rc<T> {

    pub fn new(v: T) -> Self {
        // allocate on the heap
        let inner = Box::new(
            RcInner { value: v, refcount: Cell::new(1) }
        );
        Rc {
            // consume to box and give a raw pointer back
            // this will prevent the Box from being dropped
            // SAFETY: Box does not give us a NULL pointer.
            inner: unsafe { NonNull::new_unchecked(Box::into_raw(inner)) }
        }
        // if we did: inner: &*inner the Box would be dropped here!
    }

}

// when we clone the Rc we increase the reference count, the inner value
// still points to the same location on the heap
impl<T> Clone for Rc<T> {
    fn clone(&self) -> Self {
        // if we have an Rc, the compiler does not know if the *const RcInner<T>
        // pointer is still valid
        let inner = unsafe { self.inner.as_ref() };
        let c = inner.refcount.get();
        inner.refcount.set(c + 1);
        Rc { inner: self.inner }
    }
}

impl<T> std::ops::Deref for Rc<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        // SAFETY: self.inner is a box, that is only deallocated when the last
        //         Rc goes away. We have an Rc, so the box has not been deallocated
        //         so we can deref
        &unsafe { self.inner.as_ref() }.value
    }
}

// we need to drop the box at some point
impl<T> Drop for Rc<T> {

    fn drop(&mut self) {
        let inner = unsafe { self.inner.as_ref() };
        let c = inner.refcount.get();
        if c == 1 {
            // SAFETY: we are the only reference and we should be dropped
            let _ = drop(inner);
            // we don't want to take a shared pointer and drop it, that's why
            // rust wants a *mut here, instead of *const.
            // let _ = Box::from_raw(self.inner); <-- this will fail
            // to get around this, is to use std::ptr::NonNull;
            // this tells the compiler that a pointer cannot be NULL
            let _ = unsafe { Box::from_raw(self.inner.as_ptr()) };
        } else {
            // there are other Rc's so don't drop the Box
            inner.refcount.set(c-1);
        }
    }

}
```

Now, the last thing we need to do, which is hard to understand: `PhantomData`

```rust
pub struct Rc<T> {
	inner: NonNull<RcInner<T>>,
	// we can't keep the reference count here, because of the clone
	// the reference count has to be in the value that is being cloned
	_marker: PhantomData<RcInner<T>>,
}
```

without the `_marker` Rust does not know that the type `Rc` actually owns the `T`, it's not aware that it's dropped. This is important for types that have a lifetime. 

```rust
struct Foo<'a, T: Default> { v: &'a mut T }
impl<T: Default> Drop for Foo<'_, T> {
	fn drop(&mut self) {
		std::mem::replace(self.v, T::default());
	}
} 

fn main() {
	let t = String::from("hello");
	// mutable pointer to the string
	let foo = Foo { v: &mut t };
	// string is dropped
	drop(t);
	// foo is dropped
	drop(foo);

	// the drop is actually implicit, in reality it looks like this:
	let (foo, t);
	t = String::from("hello");
	foo = Foo { v: &mut t };
	// implicit drop
	// the drop of foo will use all of the fields of Foo, which also means the String will be used
	// when Foo is dropped, it will access v, but v has already been dropped
	// the order in which drops happen matters.

	// we need PhantomData in Rc so dropping Rc will also drop the inner value, in this case Foo.
	// PhantomData treat the type Rc as if something is in it, even though it's just a pointer.
	// this means that if we wrap Foo in an Rc, the compiler knows that Foo needs to be dropped by
	// telling it that Rc owns the Foo
}
```

More about Drop Checks can be found here: https://doc.rust-lang.org/nomicon/dropck.html

Note: Rc opts out of being Sized by `T: ?Sized` - this is not talked about in this stream, too complicated.

---

Thread-Safety

The types up until now are not thread-safe, but there is a thread-safe version for `Rc`, this is `Arc`.
The difference is that instead of using a Cell, like we did inside `Rc` we *could* use an atomic counter. But, this comes with problems, it is actually solved with `RwLock`. A reader-writer lock is a Cell were counters are kept via atomics AND `borrow` and `borrow_mut` always return a value. However, if it is not possible to actually return the value, they block the respective thread. 

Example: if you call `borrow` and a different thread has an exclusive reference, the calling thread will be blocked until the exclusive reference is given up. At that point, the caller thread will resume.

---

The `std::borrow` module contains `Cow` Copy-on-Write, which is an Enum.
A Cow either contains a reference to something, or the type itself (for example reference to String or a String). Cow stands for `clone-on-write`.

Cow implements `Deref` - you can get a shared reference to the thing inside Cow.
If you want to modify the value inside, if it's a reference, it can't be modified, because it's a shared reference. That means if the value inside is currently borrowed and you want write access to it, Cow will clone it for you. Thus, you now have a value that you can write, a copy, inside Cow the value is now owned.

Cow is used when you mostly need to read, but sometimes, you also want to write. This is useful with strings. 

Example:

```rust
fn escape(s: &str) -> &str {
	// escapes special characters by cloning the input string
	// ' => \'
	// " => \"
	// but when you have a string with no special characters like "foo" there's no need to clone
	// because we didn't modify it.
	// to solve this, return a Cow!
}

fn escape(s: &'a str) -> Cow<'a, str> {
	if already_escaped(s) {
		// the "foo" case
		Cow::Borrow(s)
	} else {
		// if we encounter special characters, we need to modify
		let mut string = s.to_string();
		// ... modify string here ...
		Cow::Owned(string)
	}
}
```

Another Example (warning: this is pretty much pseudocode, but gets across the point):
```rust
impl String {
	fn from_utf8_lossy(bytes: &[u8]) -> Cow<'_, str> {
		if valid_utf8(bytes) {
			Cow::Borrowed(bytes as &str)
		} else {
			// walk the string, remove invalid utf8
			let mut bts = Vec::from(bytes);
			for bi in bts {
				// replace with INVALID_CHARACTER utf-8 symbol if not valid utf-8
				Cow::Owned(bts as String)
			}
		}
	}
}
```


