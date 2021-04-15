set(unit_m4_in_Plat_Linux console-getty.service.m4.in getty@.service.m4
    serial-getty@.service.m4)
set(unit_in_Plat_Linux)

foreach(unit_m4)
endforeach()

foreach(unit_in
  debug-shell.service.in emergency.service.in halt-local.service.in
  rescue.service.in
  systemd-ask-password-console.path.in
  systemd-ask-password-console.service.in
  systemd-ask-password-wall.path.in
  systemd-ask-password-wall.service.in
  systemd-halt.service.in
  systemd-hibernate.service.in
  systemd-hostnamed.service.in
  systemd-hybrid-sleep.service.in
  systemd-logind.service.in
  systemd-nspawn@.service.in
  systemd-poweroff.service.in
  systemd-random-seed.service.in
  systemd-reboot.service.in
  systemd-remount-fs.service.in
  systemd-shutdownd.service.in
  systemd-shutdownd.socket.in
  systemd-suspend.service.in
  systemd-sysctl.service.in
  systemd-timedated.service.in
  systemd-tmpfiles-clean.service.in
  systemd-tmpfiles-setup.service.in
  systemd-user-sessions.service.in
  user@.service.in)
    get_filename_component(unit_out ${unit_in} NAME_WLE)
    configure_file(${unit_in} ${unit_out})
endforeach()

set(user_unitfiles user/exit.target user/default.target shutdown.target
    sockets.target timers.target paths.target bluetooth.target printer.target
    sound.target smartcard.target)

set(system_unitfiles basic.target bluetooth.target cryptsetup-pre.target
    cryptsetup.target ${CMAKE_CURRENT_BINARY_DIR}/debug-shell.service
    ${CMAKE_CURRENT_BINARY_DIR}/emergency.service
    emergency.target final.target getty.target graphical.target
    ${CMAKE_CURRENT_BINARY_DIR}/halt-local.service halt.target hibernate.target
    hybrid-sleep.target kexec.target local-fs-pre.target local-fs.target
    machine.slice multi-user.target network-online.target network.target
    nss-lookup.target nss-user-lookup.target paths.target poweroff.target
    printer.target reboot.target remote-fs-pre.target remote-fs.target
    ${CMAKE_CURRENT_BINARY_DIR}/rescue.service rescue.target rpcbind.target
    shutdown.target sigpwr.target sleep.target slices.target smartcard.target
    sockets.target sound.target suspend.target swap.target sysinit.target
    system-update.target system.slice
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-ask-password-console.path
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-ask-password-console.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-ask-password-wall.path
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-ask-password-wall.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-halt.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-hibernate.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-hostnamed.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-hybrid-sleep.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-initctl.service
    systemd-initctl.socket
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-journal-flush.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-journal-gatewayd.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-journald.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-journald.socket
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-logind.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-nspawn@.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-poweroff.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-random-seed.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-reboot.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-remount-fs.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-shutdownd.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-shutdownd.socket
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-suspend.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-sysctl.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-timedated.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-tmpfiles-clean.service
    systemd-tmpfiles-clean.timer
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-tmpfiles-setup.service
    ${CMAKE_CURRENT_BINARY_DIR}/systemd-user-sessions.service
    time-sync.target
    timers.target
    umount.target
    user.slice
    ${CMAKE_CURRENT_BINARY_DIR}/user@.service
    x-.slice
    )

install(FILES ${user_unitfiles} DESTINATION ${RelDir_UserUnitfiles})
install(FILES ${system_unitfiles} DESTINATION ${RelDir_SystemUnitfiles})