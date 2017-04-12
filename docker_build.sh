#!/bin/bash

NAME="pickapp/pyportredirector"
VERSION=0.1

docker rmi -f ${NAME}:${VERSION} 2>/dev/null
docker rmi -f ${NAME}:latest 2>/dev/null
docker build --rm -t ${NAME}:${VERSION} -t ${NAME}:latest .
docker push ${NAME}:${VERSION}
docker push ${NAME}:latest
