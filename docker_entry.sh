#!/bin/sh

# Is it server?
server=0; for arg in "$@"; do [ "$arg" == "-l" ] && server=1 && break; done

# Check if iptables is usable on server
if [ ${server} -ne 0 ]; then
    iptables -L &>/dev/null
    if [ $? -ne 0 ]; then
        echo "You need to start docker in privileged mode and with host networking:" >&2
        echo "    docker run --net=host --privileged ..." >&2
        exit 1
    fi
fi

exec /usr/local/bin/python3 -u /opt/portredirector.py $@
