InitWare
========

<img src="doc/brand/logotype.png" width=400>

**InitWare isn't ready to use yet!**

The InitWare suite is a middleware package that allows you to manage services
and system resources as logical entities called units. Units are manageable by a
uniform interface, may specify dependencies and other relationships to other
units, and are automatically scheduled by the InitWare system

InitWare is derived from the X Desktop Group's
[systemd](http://www.freedesktop.org/wiki/Software/systemd), version 208, and
provides similar APIs, with an option to build in *systemd mode*, in which the
exact same D-Bus APIs are provided. InitWare is differentiated from systemd by
its greater portability, more controlled scope, and a more modular approach to
questions of architecture.

Requirements
------------

The following platforms are supported:

- FreeBSD (13.0+)
- NetBSD (8.0+)
- GNU/Linux (4.0+)


To build InitWare, a full installation (including development libraries and
headers) is required of at least 8the following components:

- a C toolchain supporting GNU C extensions, e.g. GNU CC or LLVM/Clang
- CMake 3.9+
- D-Bus 1.4+

Licencing
---------

InitWare is licensed under the GNU Library GPL, version 2.1 or later, except for
the following files:

- sd-daemon.[ch] and sd-readahead.[ch], which are subject to the MIT Licence.
- src/shared/MurmurHash3.c, which is in the public domain.
- src/journal/lookup3.c, which is in the public domain.
