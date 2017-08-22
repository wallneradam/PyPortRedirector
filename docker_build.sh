#!/bin/bash

NAME="pickapp/pyportredirector"
VERSION=`cat ./portredirector.py | grep "__version__" | cut -d '"' -f2`

[ "$1" == "pypy" ] && VERSION="$VERSION-pypy"

if [ "$1" != "pypy" ]; then
    docker build --rm -t ${NAME}:${VERSION} -t ${NAME}:latest . \
        && docker push ${NAME}:latest
fi
if [ "$1" == "pypy" ]; then
    docker build -f Dockerfile.pypy --rm -t ${NAME}:${VERSION} -t ${NAME}:pypy . \
        && docker push ${NAME}:pypy
fi

[ $? -eq 0 ] && docker push ${NAME}:${VERSION}

# Remove untagged images
docker images --no-trunc | grep "<none>" | awk "{print \$3}" | xargs docker rmi -f