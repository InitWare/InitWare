/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#define BUS_ERROR_NO_SUCH_UNIT SCHEDULER_DBUS_INTERFACE ".NoSuchUnit"
#define BUS_ERROR_NO_SUCH_JOB SCHEDULER_DBUS_INTERFACE ".NoSuchJob"
#define BUS_ERROR_NOT_SUBSCRIBED SCHEDULER_DBUS_INTERFACE ".NotSubscribed"
#define BUS_ERROR_INVALID_PATH SCHEDULER_DBUS_INTERFACE ".InvalidPath"
#define BUS_ERROR_INVALID_NAME SCHEDULER_DBUS_INTERFACE ".InvalidName"
#define BUS_ERROR_UNIT_TYPE_MISMATCH SCHEDULER_DBUS_INTERFACE ".UnitTypeMismatch"
#define BUS_ERROR_UNIT_EXISTS SCHEDULER_DBUS_INTERFACE ".UnitExists"
#define BUS_ERROR_NOT_SUPPORTED SCHEDULER_DBUS_INTERFACE ".NotSupported"
#define BUS_ERROR_INVALID_JOB_MODE SCHEDULER_DBUS_INTERFACE ".InvalidJobMode"
#define BUS_ERROR_ONLY_BY_DEPENDENCY SCHEDULER_DBUS_INTERFACE ".OnlyByDependency"
#define BUS_ERROR_NO_ISOLATION SCHEDULER_DBUS_INTERFACE ".NoIsolation"
#define BUS_ERROR_LOAD_FAILED SCHEDULER_DBUS_INTERFACE ".LoadFailed"
#define BUS_ERROR_MASKED SCHEDULER_DBUS_INTERFACE ".Masked"
#define BUS_ERROR_JOB_TYPE_NOT_APPLICABLE SCHEDULER_DBUS_INTERFACE ".JobTypeNotApplicable"
#define BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE SCHEDULER_DBUS_INTERFACE ".TransactionIsDestructive"
#define BUS_ERROR_TRANSACTION_JOBS_CONFLICTING SCHEDULER_DBUS_INTERFACE ".TransactionJobsConflicting"
#define BUS_ERROR_TRANSACTION_ORDER_IS_CYCLIC SCHEDULER_DBUS_INTERFACE ".TransactionOrderIsCyclic"
#define BUS_ERROR_SHUTTING_DOWN SCHEDULER_DBUS_INTERFACE ".ShuttingDown"
#define BUS_ERROR_NO_SUCH_PROCESS SCHEDULER_DBUS_INTERFACE ".NoSuchProcess"
#define BUS_ERROR_JOB_FAILED SCHEDULER_DBUS_INTERFACE ".JobFailed"
