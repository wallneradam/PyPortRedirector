#!/bin/bash

NAME="pickapp/pyportredirector"
VERSION=0.2.2

[ "$1" == "pypy" ] && VERSION="$VERSION-pypy"

docker rmi -f ${NAME}:${VERSION} 2>/dev/null

if [ "$1" != "pypy" ]; then
    docker rmi -f ${NAME}:latest 2>/dev/null
    docker build --rm -t ${NAME}:${VERSION} -t ${NAME}:latest . \
        && docker push ${NAME}:latest
fi
if [ "$1" == "pypy" ]; then
    docker rmi -f ${NAME}:pypy 2>/dev/null
    docker build -f Dockerfile.pypy --rm -t ${NAME}:${VERSION} -t ${NAME}:pypy . \
        && docker push ${NAME}:pypy
fi

[ $? -eq 0 ] && docker push ${NAME}:${VERSION}
