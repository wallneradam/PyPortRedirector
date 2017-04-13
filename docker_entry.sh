#!/bin/bash

server=0;
interface=""

# Parse params
_interface=0
args=()
for arg in "$@"; do
    # Interface
    [ "$arg" == "-i" ] && [ ${_interface} -eq 0 ] && _interface=1 && continue
    [ ${_interface} -eq 1 ] && _interface=0 && interface="$arg" && continue

    # Is it server?
    [ "$arg" == "-l" ] && server=1;

    args+=(${arg})
done

if [ ${server} -ne 0 ]; then
    # Check if iptables is usable on server
    iptables -L &>/dev/null
    if [ $? -ne 0 ]; then
        echo "You need to start docker in privileged mode and with host networking:" >&2
        echo "    docker run --net=host --privileged ..." >&2
        exit 1
    fi

    # Enable local routing
    [ "$interface" != "" ] && eval "echo -n 1 >/proc/sys/net/ipv4/conf/${interface}/route_localnet"
fi

exec /usr/local/bin/python3 -u /opt/portredirector.py ${args[@]}
