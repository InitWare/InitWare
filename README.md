![InitWare](http://brand.initware.com/assets/page-logo.png)

Middleware suite for system and service management.

***InitWare isn't ready to use yet!!***
Unless you are doing so for fun and fun alone, or to contribute, you most
likely do **not** want to try to install InitWare until a first release is made!

InitWare is a middleware suite that allows you to manage services
and system resources as logical entities called units. Units are manageable by a
uniform interface, may specify dependencies and other relationships to other
units, and are automatically scheduled by the InitWare system

It is from the X Desktop Group's
[`systemd`](http://www.freedesktop.org/wiki/Software/systemd), version 208, that
InitWare has been forked.
Similar APIs to systemd are still provided, with an option to build in
*systemd mode*, in which the exact same D-Bus APIs are provided. Where feasible,
core features of more recent releases of `systemd` will be ported or supported
by alternative means.

InitWare is differentiated from systemd by its superior portability, more
controlled project scope, and a modular approach to questions of architecture.
The [Roadmap](wiki/Roadmap) details some future plans.


Requirements
------------

The following platforms are supported:

- FreeBSD (13.0+) as user manager.
- NetBSD (8.0+) as user manager.
- GNU/Linux (4.0+) as system or user manager.


To build InitWare, a full installation (including development libraries and
headers) is required of at least the following components:

- a C toolchain supporting GNU C extensions, e.g. GNU CC or LLVM/Clang
- CMake 3.9+
- D-Bus 1.4+
- On FreeBSD/NetBSD/OpenBSD:
    - [ePoll-Shim](https://github.com/jiixyj/epoll-shim) v0.0.20210310+
      (provided as `libepoll-shim` in Ports)
    - [libiNotify-KQueue](https://github.com/libinotify-kqueue/libinotify-kqueue)
      v0.0.20180201+ (provided as `libinotify` in Ports, pkgsrc, and OpenPorts)

The runtime requirements are:

- D-Bus 1.4+
- On FreeBSD:
    - `fdescfs` mounted at `/dev/fd`
- On NetBSD:
    - `procfs` mounted at `/proc`

Licencing
---------

InitWare is licensed under the GNU Library GPL, version 2.1 or later, except for
the following files:

- sd-daemon.[ch] and sd-readahead.[ch], which are subject to the MIT Licence.
- src/shared/MurmurHash3.c, which is in the public domain.
- src/journal/lookup3.c, which is in the public domain.
