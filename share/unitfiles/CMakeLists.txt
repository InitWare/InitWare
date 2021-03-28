set(user_unitfiles user/exit.target user/default.target shutdown.target
    sockets.target timers.target paths.target bluetooth.target printer.target
    sound.target smartcard.target)

install(FILES ${user_unitfiles} DESTINATION ${RelDir_UserUnitfiles})