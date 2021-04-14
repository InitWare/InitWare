These files are of foreign origin, neither inherited from the systemd project
nor written by the InitWare developers, and licenced differently to the rest of
InitWare, which is LGPL v2.1 or later:

- `sd-daemon.[ch]`, `sd-readahead.[ch]`: MIT Licence.
- `lib/shared/MurmurHash3.c`: in the public domain.
- `src/journal/lookup3.c`: in the public domain.
- `lib/compat/head/printf.h`: Modified BSD Licence (2-clause). Origin: FreeBSD
- `lib/compat/head/compat.h.in`: Mixed Modified BSD Licence (2-clause) with
  one MIT fragment.
- `cmd/rcng/netbsd/rc`, `cmd/rcng/netbsd/rc.subr.patch`: Modified BSD Licence
(2-clause). Origin: NetBSD.

These files are entirely authored by the InitWare team, but are too
trivial/obvious in implementation to be copyrightable. They are therefore in the
public domain implicitly, but if you require a formal declaration to that
effect, let this satisfy you:

- `cmd/rcng/wait4pipe.c`: in the public domain