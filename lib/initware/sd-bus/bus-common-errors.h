#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include "bus-error.h"
#include "sd-bus.h"

#define BUS_ERROR_NO_SUCH_UNIT SVC_DBUS_INTERFACE ".NoSuchUnit"
#define BUS_ERROR_NO_UNIT_FOR_PID SVC_DBUS_INTERFACE ".NoUnitForPID"
#define BUS_ERROR_UNIT_EXISTS SVC_DBUS_INTERFACE ".UnitExists"
#define BUS_ERROR_LOAD_FAILED SVC_DBUS_INTERFACE ".LoadFailed"
#define BUS_ERROR_JOB_FAILED SVC_DBUS_INTERFACE ".JobFailed"
#define BUS_ERROR_NO_SUCH_JOB SVC_DBUS_INTERFACE ".NoSuchJob"
#define BUS_ERROR_NOT_SUBSCRIBED SVC_DBUS_INTERFACE ".NotSubscribed"
#define BUS_ERROR_ALREADY_SUBSCRIBED SVC_DBUS_INTERFACE ".AlreadySubscribed"
#define BUS_ERROR_ONLY_BY_DEPENDENCY SVC_DBUS_INTERFACE ".OnlyByDependency"
#define BUS_ERROR_TRANSACTION_JOBS_CONFLICTING                                 \
	SVC_DBUS_INTERFACE ".TransactionJobsConflicting"
#define BUS_ERROR_TRANSACTION_ORDER_IS_CYCLIC                                  \
	SVC_DBUS_INTERFACE ".TransactionOrderIsCyclic"
#define BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE                                   \
	SVC_DBUS_INTERFACE ".TransactionIsDestructive"
#define BUS_ERROR_UNIT_MASKED SVC_DBUS_INTERFACE ".UnitMasked"
#define BUS_ERROR_JOB_TYPE_NOT_APPLICABLE                                      \
	SVC_DBUS_INTERFACE ".JobTypeNotApplicable"
#define BUS_ERROR_NO_ISOLATION SVC_DBUS_INTERFACE ".NoIsolation"
#define BUS_ERROR_SHUTTING_DOWN SVC_DBUS_INTERFACE ".ShuttingDown"
#define BUS_ERROR_SCOPE_NOT_RUNNING SVC_DBUS_INTERFACE ".ScopeNotRunning"

#define BUS_ERROR_NO_SUCH_MACHINE SVC_MACHINED_DBUS_INTERFACE ".NoSuchMachine"
#define BUS_ERROR_NO_SUCH_IMAGE SVC_MACHINED_DBUS_INTERFACE ".NoSuchImage"
#define BUS_ERROR_NO_MACHINE_FOR_PID                                           \
	SVC_MACHINED_DBUS_INTERFACE ".NoMachineForPID"
#define BUS_ERROR_MACHINE_EXISTS SVC_MACHINED_DBUS_INTERFACE ".MachineExists"
#define BUS_ERROR_NO_PRIVATE_NETWORKING                                        \
	SVC_MACHINED_DBUS_INTERFACE ".NoPrivateNetworking"

#define BUS_ERROR_NO_SUCH_SESSION SVC_SESSIOND_DBUS_INTERFACE ".NoSuchSession"
#define BUS_ERROR_NO_SESSION_FOR_PID                                           \
	SVC_SESSIOND_DBUS_INTERFACE ".NoSessionForPID"
#define BUS_ERROR_NO_SUCH_USER SVC_SESSIOND_DBUS_INTERFACE ".NoSuchUser"
#define BUS_ERROR_NO_USER_FOR_PID SVC_SESSIOND_DBUS_INTERFACE ".NoUserForPID"
#define BUS_ERROR_NO_SUCH_SEAT SVC_SESSIOND_DBUS_INTERFACE ".NoSuchSeat"
#define BUS_ERROR_SESSION_NOT_ON_SEAT                                          \
	SVC_SESSIOND_DBUS_INTERFACE ".SessionNotOnSeat"
#define BUS_ERROR_NOT_IN_CONTROL SVC_SESSIOND_DBUS_INTERFACE ".NotInControl"
#define BUS_ERROR_DEVICE_IS_TAKEN SVC_SESSIOND_DBUS_INTERFACE ".DeviceIsTaken"
#define BUS_ERROR_DEVICE_NOT_TAKEN SVC_SESSIOND_DBUS_INTERFACE ".DeviceNotTaken"
#define BUS_ERROR_OPERATION_IN_PROGRESS                                        \
	SVC_SESSIOND_DBUS_INTERFACE ".OperationInProgress"
#define BUS_ERROR_SLEEP_VERB_NOT_SUPPORTED                                     \
	SVC_SESSIOND_DBUS_INTERFACE ".SleepVerbNotSupported"

#define BUS_ERROR_AUTOMATIC_TIME_SYNC_ENABLED                                  \
	"org.freedesktop.timedate1.AutomaticTimeSyncEnabled"

#define BUS_ERROR_NO_SUCH_PROCESS SVC_DBUS_INTERFACE ".NoSuchProcess"

#define BUS_ERROR_NO_NAME_SERVERS "org.freedesktop.resolve1.NoNameServers"
#define BUS_ERROR_INVALID_REPLY "org.freedesktop.resolve1.InvalidReply"
#define BUS_ERROR_NO_SUCH_RR "org.freedesktop.resolve1.NoSuchRR"
#define BUS_ERROR_NO_RESOURCES "org.freedesktop.resolve1.NoResources"
#define BUS_ERROR_CNAME_LOOP "org.freedesktop.resolve1.CNameLoop"
#define BUS_ERROR_ABORTED "org.freedesktop.resolve1.Aborted"
#define _BUS_ERROR_DNS "org.freedesktop.resolve1.DnsError."

#define BUS_ERROR_NO_SUCH_TRANSFER "org.freedesktop.import1.NoSuchTransfer"
#define BUS_ERROR_TRANSFER_IN_PROGRESS                                         \
	"org.freedesktop.import1.TransferInProgress"

BUS_ERROR_MAP_ELF_USE(bus_common_errors);
