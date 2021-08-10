echo "Configuring InitWare as an auxiliary service manager."
svcctl set-default auxiliary-manager.target
svcctl preset systemd-journald.service systemd-journald.socket systemd-logind.service