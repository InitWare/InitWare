# General Style Guide

This document contains style guidelines which apply universally to InitWare,
i.e. to documentation and code alike

## Symbolic Link Nomenclature

- The file to which a symbolic link points shall be called the *source* or
  *source file*.
- The symbolic link itself (the directory entry pointing to the source file)
  shall be called the *link*.
- The term "target" shall be avoided; it is confusing defined in opposite terms
  by the GNU Coreutils and NetBSD `LN(1)` manual pages.
- The terms "to" and "from" shall be avoided; they are ambiguous.