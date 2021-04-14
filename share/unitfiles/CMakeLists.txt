set(unit_m4_in_Plat_Linux console-getty.service.m4.in getty@.service.m4
    serial-getty@.service.m4)
set(unit_in_Plat_Linux)

foreach(unit_m4)
endforeach()

foreach(unit_in debug-shell.service.in emergency.service.in )
endforeach()

set(user_unitfiles user/exit.target user/default.target shutdown.target
    sockets.target timers.target paths.target bluetooth.target printer.target
    sound.target smartcard.target)

set(system_unitfiles basic.target bluetooth.target cryptsetup-pre.target
    cryptsetup.target${CMAKE_CURRENT_SOURCE_DIR}/debug-shell.service
    ${CMAKE_CURRENT_SOURCE_DIR}/emergency.service
    emergency.target final.target getty.target graphical.target
    ${CMAKE_CURRENT_SOURCE_DIR}/halt-local.service halt.target hibernate.target
    hybrid-sleep.target kexec.target local-fs-pre.target local-fs.target
    machine.slice multi-user.target network-online.target network.target
    nss-lookup.target nss-user-lookup.target paths.target poweroff.target
    printer.target reboot.target remote-fs-pre.target remote-fs.target
    ${CMAKE_CURRENT_SOURCE_DIR}/rescue.service rescue.target rpcbind.target
    shutdown.target sigpwr.target sleep.target slices.target smartcard.target
    sockets.target sound.target suspend.target swap.target sysinit.target
    ${CMAKE_CURRENT_SOURCE_DIR}/journal-syslog.socket system-update.target
    system.slice)

install(FILES ${user_unitfiles} DESTINATION ${RelDir_UserUnitfiles})