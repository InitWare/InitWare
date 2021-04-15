#include <dbus/dbus.h>

#include "install.h"
#include "logs-show.h"
#include "time-util.h"

enum action {
        ACTION_INVALID,
        ACTION_SYSTEMCTL,
        ACTION_HALT,
        ACTION_POWEROFF,
        ACTION_REBOOT,
        ACTION_KEXEC,
        ACTION_EXIT,
        ACTION_SUSPEND,
        ACTION_HIBERNATE,
        ACTION_HYBRID_SLEEP,
        ACTION_RUNLEVEL2,
        ACTION_RUNLEVEL3,
        ACTION_RUNLEVEL4,
        ACTION_RUNLEVEL5,
        ACTION_RESCUE,
        ACTION_EMERGENCY,
        ACTION_DEFAULT,
        ACTION_RELOAD,
        ACTION_REEXEC,
        ACTION_RUNLEVEL,
        ACTION_CANCEL_SHUTDOWN,
        _ACTION_MAX
};

enum dependency {
        DEPENDENCY_FORWARD,
        DEPENDENCY_REVERSE,
        DEPENDENCY_AFTER,
        DEPENDENCY_BEFORE,
};

enum transport { TRANSPORT_NORMAL, TRANSPORT_SSH, TRANSPORT_POLKIT };

extern char **arg_types;
extern char **arg_states;
extern char **arg_properties;
extern bool arg_all;
extern bool original_stdout_is_tty;
extern enum dependency arg_dependency;
extern const char *arg_job_mode;
extern UnitFileScope arg_scope;
extern bool arg_no_block;
extern bool arg_no_legend;
extern bool arg_no_pager;
extern bool arg_no_wtmp;
extern bool arg_no_wall;
extern bool arg_no_reload;
extern bool arg_show_types;
extern bool arg_ignore_inhibitors;
extern bool arg_dry;
extern bool arg_quiet;
extern bool arg_full;
extern int arg_force;
extern bool arg_ask_password;
extern bool arg_runtime;
extern char **arg_wall;
extern const char *arg_kill_who;
extern int arg_signal;
extern const char *arg_root;
extern usec_t arg_when;
extern enum action arg_action;
extern enum transport arg_transport;
extern char *arg_host;
extern char *arg_user;
extern unsigned arg_lines;
extern OutputMode arg_output;
extern bool arg_plain;

extern bool private_bus;

_noreturn_ void halt_now(enum action a);

void pager_open_if_enabled(void);
bool avoid_bus(void);
void warn_wall(enum action a);
int check_inhibitors(DBusConnection *bus, enum action a);
int reboot_with_logind(DBusConnection *bus, enum action a);

/*
 * Actions
 */
int list_units(DBusConnection *bus, char **args);
int list_unit_files(DBusConnection *bus, char **args);
int list_sockets(DBusConnection *bus, char **args);
int list_jobs(DBusConnection *bus, char **args);
int daemon_reload(DBusConnection *bus, char **args);
int cancel_job(DBusConnection *bus, char **args);
int start_unit(DBusConnection *bus, char **args);
int kill_unit(DBusConnection *bus, char **args);

int check_unit_active(DBusConnection *bus, char **args);
int check_unit_failed(DBusConnection *bus, char **args);
int kill_unit(DBusConnection *bus, char **args);
int show(DBusConnection *bus, char **args);
int snapshot(DBusConnection *bus, char **args);
int delete_snapshot(DBusConnection *bus, char **args);
int show_environment(DBusConnection *bus, char **args);
int set_environment(DBusConnection *bus, char **args);
int start_special(DBusConnection *bus, char **args);

int reset_failed(DBusConnection *bus, char **args);
int enable_unit(DBusConnection *bus, char **args);
int unit_is_enabled(DBusConnection *bus, char **args);
int enable_unit(DBusConnection *bus, char **args);

int switch_root(DBusConnection *bus, char **args);
int list_dependencies(DBusConnection *bus, char **args);
int get_default(DBusConnection *bus, char **args);
int set_property(DBusConnection *bus, char **args);