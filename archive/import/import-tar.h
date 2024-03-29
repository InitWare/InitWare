#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "import-util.h"
#include "macro.h"
#include "sd-event.h"

typedef struct TarImport TarImport;

typedef void (*TarImportFinished)(TarImport *import, int error, void *userdata);

int tar_import_new(TarImport **import, sd_event *event, const char *image_root,
	TarImportFinished on_finished, void *userdata);
TarImport *tar_import_unref(TarImport *import);

DEFINE_TRIVIAL_CLEANUP_FUNC(TarImport *, tar_import_unref);

int tar_import_pull(TarImport *import, const char *url, const char *local,
	bool force_local, ImportVerify verify);
