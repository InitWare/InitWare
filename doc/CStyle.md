# C Style Guide

InitWare code is subject to a style guide. This document describes the style
expected of code written in C-like languages.
All code in new files or files in which the new style already predominantes 
should conform;
in the case of modifications to files which retain the older style from the
systemd project, the systemd style guide ought to be followed instead.

## Basics

- Indentation is by 8 characters.
- Structures are named in MixedCase, while variables and functions get
  snake_case.
- Function call argument lists shall *not* be divided from the function
  expression:

      foo();

  and not

      foo ();

## Curly Brackets

- Curly Bracketing shall follow the principles of BSD Kernel Normal Form;
  the opening curly bracket of a function shall appear on a dedicated line:
  
      int hello()
      {
              return 0;
      }
  
  while all other curly brackets shall come one space after the last part of the
  syntactic element to which they are bound:

      if (true) {
              do_this();
              do_that();
      }

  In the exceptional case of a compound statement directly attached to the
  statement list of an enclosing compound statement, then the curly bracket does
  retain its own line:

      {
              int x;

              do_with(x);
      }

## Include-File Ordering

Include files shall be sorted into groups - within which includes are sorted
alphabetically unless specified otherwise - in the following order:

1. The kernel include files (`<sys/*>`). Within these, either
  `<sys/param.h` or `<sys/types.h` comes first if one is included, but not both.
  The remainder are sorted alphabetically.

2. Linux architecture-specific include files (`<asm/*>`).

3. Linux kernel include files (`<linux/*>`).

4. Networking include files (`<net/*>`, `<netinet/*>`, `<protocols/`).

5. System C includes (`<*>` noninclusive)

6. Host library includes and includes public to the project (`<*>`, `<*/*>` both
  noninclusive).

7. All other includes.

It is often the case that conditional inclusion of files is required. In this
case, conditional includes ought to be grouped as above, but appear as a
separate set of groups which follow the groups of unconditional includes.

## Misc

- Variables and functions *must* be static, unless they have a
  protoype, and are supposed to be exported.


- The destructors always unregister the object from the next bigger
  object, not the other way around

- To minimize strict aliasing violations we prefer unions over casting

- For robustness reasons destructors should be able to destruct
  half-initialized objects, too

- Error codes are returned as negative Exxx. i.e. return -EINVAL. There
  are some exceptions: for constructors its is OK to return NULL on
  OOM. For lookup functions NULL is fine too for "not found".

  Be strict with this. When you write a function that can fail due to
  more than one cause, it *really* should have "int" as return value
  for the error code.

- Don't bother with error checking if writing to stdout/stderr worked.

- Do not log errors from "library" code, only do so from "main
  program" code.

- Always check OOM. There's no excuse. In program code you can use
  "log_oom()" for then printing a short message.

- Do not issue NSS requests (that includes user name and host name
  lookups) from the main daemon as this might trigger deadlocks when
  those lookups involve synchronously talking to services that we
  would need to start up

- Don't synchronously talk to any other service, due to risk of
  deadlocks

- Avoid fixed sized string buffers, unless you really know the maximum
  size and that maximum size is small. They are a source of errors,
  since they result in strings to be truncated. Often it is nicer to
  use dynamic memory, or alloca(). If you do allocate fixed size
  strings on the stack, then it's probably only OK if you either use a
  maximum size such as LINE_MAX, or count in detail the maximum size a
  string can have. Or in other words, if you use "char buf[256]" then
  you are likely doing something wrong!

- Stay uniform. For example, always use "usec_t" for time
  values. Don't usec mix msec, and usec and whatnot.

- Make use of _cleanup_free_ and friends. It makes your code much
  nicer to read!

- Be exceptionally careful when formatting and parsing floating point
  numbers. Their syntax is locale dependent (i.e. "5.000" in en_US is
  generally understood as 5, while on de_DE as 5000.).

- Please use streq() and strneq() instead of strcmp(), strncmp() where applicable.

- Please do not allocate variables on the stack in the middle of code,
  even if C99 allows it. Wrong:

    {
            a = 5;
            int b;
            b = a;
    }

  Right:

    {
            int b;
            a = 5;
            b = a;
    }


- Unless you allocate an array, "double" is always the better choice
  than "float". Processors speak "double" natively anyway, so this is
  no speed benefit, and on calls like printf() "float"s get upgraded
  to "double"s anyway, so there is no point.

- Don't invoke functions when you allocate variables on the stack. Wrong:

    {
            int a = foobar();
            uint64_t x = 7;
    }

  Right:

    {
            int a;
            uint64_t x = 7;

            a = foobar();
    }

- Use "goto" for cleaning up, and only use it for that. i.e. you may
  only jump to the end of a function, and little else.

- Think about the types you use. If a value cannot sensibly be
  negative don't use "int", but use "unsigned".

- Don't use types like "short". They *never* make sense. Use ints,
  longs, long longs, all in unsigned+signed fashion, and the fixed
  size types uint32_t and so on, but nothing else.
