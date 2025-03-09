#!/bin/bash

# Handle -d and -h
OPTSTRING=":dh"
DEBUG=false
while getopts ${OPTSTRING} opt; do
	case ${opt} in
	d)
		DEBUG=true
		;;
	h)
        echo "Run \`./run.sh\` to run in release mode"
        echo "Use \`-d\` to run in debug"
		exit 1
		;;
	?)
		echo "Use only -d for debug mode and -h for help"
		exit 1
		;;
	esac
done

INTERFACE_NAME="tun0"

BIN_NAME="nust"
if [ "$DEBUG" = true ] ; then
    cargo build
    CARGO_DIR="./target/debug"
else
    cargo build -r
    CARGO_DIR="./target/release"
fi
sudo setcap cap_net_admin+ep $CARGO_DIR/$BIN_NAME # Give perms to do network stuff
$CARGO_DIR/$BIN_NAME & # Start running main.rs
pid=$!
sudo ip addr add 192.168.0.1/24 dev $INTERFACE_NAME
sudo ip link set up dev $INTERFACE_NAME
trap "kill $pid" INT TERM
wait $pid
