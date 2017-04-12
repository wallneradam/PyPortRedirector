FROM python:3.6-alpine

MAINTAINER Adam Wallner <adam.wallner@gmail.com>

COPY portredirector.py /opt/
COPY docker_entry.sh /opt/

RUN \
    # Install needed packages
    apk add --no-cache iptables binutils bash gcc musl-dev make \
    # find_library not working good in Python on Alpine Linux, so we create the needed symlinks insetead
    && ln -s /lib/ld-musl-x86_64.so.1 /lib/libc.so \
    && ln -s /usr/lib/libxtables.so.11 /lib/libxtables.so \
    && ln -s /usr/lib/libip4tc.so.0 /lib/libip4tc.so \
    && ln -s /usr/lib/libip6tc.so.0 /lib/libip6tc.so \
    # Install python-iptables package
    && pip3 install --upgrade uvloop \
    && pip3 install --upgrade python-iptables \
    # Clean unneeded packages
    && apk del gcc musl-dev make

WORKDIR /opt

ENTRYPOINT ["/opt/docker_entry.sh"]
