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
The [Roadmap](wiki/Roadmap) details some future plans.


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

Licencing
---------

Most of InitWare is licensed under the GNU Library GPL, version 2.1 or later,
but some files are under other terms. See [doc/Licences.md] for details.