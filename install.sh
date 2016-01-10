#!/usr/bin/env bash
if [ $(id -u) != "0" ] ; then
    echo "read the script and re-run as root"
    exit 1
fi
set -e
set -x
mkdir -p /opt/urc/
cp urc.py /opt/urc/
cp hubs.txt /opt/urc/
chmod 700 /opt/urc/urc.py
chmod 700 /opt/urc/hubs.txt
echo "urc.py installed to /opt/urc/urc.py"
if [ -e /etc/systemd/system ] ; then
    cp urc.service /etc/systemd/system/
    echo 'do "systemctl enable urc" to enable urc on startup'
else
    echo 'systemd unit not installed'
fi
