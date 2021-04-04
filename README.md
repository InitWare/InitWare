![InitWare](http://brand.initware.com/assets/page-logo.png)

***InitWare isn't ready to use yet!!***
Unless you are doing so for fun and fun alone, or to contribute, you most
likely do **not** want to try to install InitWare until a first release is made!

The **InitWare Suite of Middleware** allows you to manage services
and system resources as logical entities called units. Units are manageable by a
uniform interface, may specify dependencies and other relationships to other
units, and are automatically scheduled by the InitWare Manager, a service
management (or "init") system.

[Systemd](http://www.freedesktop.org/wiki/Software/systemd), version 208, is
the original codebase from which InitWare has been forked.
Similar APIs to systemd are still provided, with an option to build in
*systemd mode*, in which the exact same D-Bus APIs are provided. Where feasible,
core features of more recent releases of systemd will be ported or supported
by alternative means.

InitWare is differentiated from systemd by its superior portability, defined
project scope, and a modular approach to questions of architecture.
The [Roadmap](wiki/Roadmap) details some plans for the future development of
the InitWare Suite.


Requirements
------------

The following platforms are supported:

- DragonFly BSD (5.8+) as user manager.
- FreeBSD (13.0+) as user manager.
- GNU/Linux (3.6+) as system or user manager.
- NetBSD (8.0+) as user manager.

We hope to support (recent versions of) OpenBSD, and possibly also Illumos, in
the near future.

**Required runtime dependencies**:

- D-Bus 1.4+
- On all BSD platforms:
    - *[libepoll-shim](https://github.com/jiixyj/epoll-shim)* v0.0.20210310+
      (provided as `libepoll-shim` in Ports)
    - *[libinotify-kqueue](https://github.com/libinotify-kqueue/libinotify-kqueue)*
      v0.0.20180201+ (provided as `libinotify` in Ports, pkgsrc, and OpenPorts)

**Optional runtime dependencies**:

- On GNU/Linux:
    - UDev or Eudev (for `.device` unit support)
- On DragonFly BSD:
    - `udevd` running (for `.device` unit support)
- On FreeBSD:
    - *libudev-devd* (for `.device` unit support)

To build InitWare, any libraries listed above must be present complete with
their associated development libraries. Additionally required are the
following:

- a C toolchain supporting GNU C extensions, e.g. GNU CC or LLVM/Clang
- Typical build prerequisites (e.g. `build-essential` on Debian)
- CMake 3.9+
- GPerf
- M4, Awk

Building is done in the typical CMake way, i.e. `cmake && make && make install`.

Licencing
---------

Most of InitWare is licensed under the GNU Library GPL, version 2.1 or later,
but some files are under other terms. See [doc/Licences.md](doc/Licences.md)
for details. In particular, where a file does not implement any algorithm or
technology eligible for copyright (e.g. where the functionality is basic and
obviously implementable only in one way), these are released explicitly into
the public domain, as copyright would be anyway uneforceable.

Further reading
---------------

- [Repository Tour](https://github.com/InitWare/InitWare/wiki/Repository-Tour):
  A brief overview of the layout of the repository.
- [C Style Guide](doc/Style.md): The standards of style by which code in C-like
  languages is written in InitWare.
- [Roadmap](https://github.com/InitWare/InitWare/wiki/Roadmap):
  Future plans for InitWare.
- [PTGroups](https://github.com/InitWare/InitWare/wiki/PTGroups):
  Describes PTGroups, the simple abstraction layer over the PROC filter for
  Kernel Queues, which provides advanced (CGroups-like) process tracking on the
  BSD ports of InitWare.
- [Porting Notes](https://github.com/InitWare/InitWare/wiki/Porting-Notes):
  Notes on porting InitWare, and details of how the initial port (from GNU/Linux
  to NetBSD) was done.
<!-- - [Changes](https://github.com/InitWare/InitWare/wiki/Changes):
  Enumerates in summary significant changes made to InitWare. A page worth
  reading for anyone who wants to know in what respects InitWare differs from
  systemd.-->
