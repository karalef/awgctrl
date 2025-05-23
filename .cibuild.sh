#!/usr/bin/env bash
set -e
set -x

# !! This script is meant for use in CI build use only !!

if [ "$(uname -s)" != "Linux" ]; then
    echo "This script is only for Linux"
    exit 1


# Configure a WireGuard interface.
sudo ip link add wg0 type wireguard
sudo ip link set up wg0

# Set up wireguard-go on all OSes.
git clone https://git.zx2c4.com/wireguard-go
cd wireguard-go
make

${SUDO} mv ./wireguard-go /usr/local/bin/wireguard-go
cd ..
${SUDO} rm -rf ./wireguard-go
