ln -sf auxiliary-manager.target ${1}/lib/InitWare/system/default.target
mkdir -p ${1}/lib/InitWare/system/sysinit.target.wants ${1}/lib/InitWare/system/sockets.target.wants
ln -sf ../systemd-journald.service ${1}/lib/InitWare/system/sysinit.target.wants/
ln -sf ../systemd-journald.socket ${1}/lib/InitWare/system/sockets.target.wants/
