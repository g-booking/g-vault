#!/bin/bash
VERSION=0.90
rm -f /root/gvault_install-$VERSION.sh
cd /gbooking/g-vault

TAR=`tar -czf - sys/*g* lib/g* bin/g* installer/g_vault_install.sh | base64 -w0`

echo "

# gVault installation script.
apt-get install -y tar >/dev/null 2>/dev/null
dnf     install -y tar >/dev/null 2>/dev/null

mkdir ./gvault_temp_directory
cd    ./gvault_temp_directory

echo $TAR | base64 -d | tar zxf -

sh installer/g_vault_install.sh
cd ..
rm -rf ./gvault_temp_directory
rm -r  ./gvault_install-$VERSION.sh
" >/root/gvault_install-$VERSION.sh

echo "I've made [ /root/gvault_install-$VERSION.sh ] as an installation"
