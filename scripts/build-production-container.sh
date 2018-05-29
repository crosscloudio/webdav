#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# This script builds two docker images - in the first there are dependencies
# installed which are then copied to the filesystem and then (together with the
# mobiledav source code) to the final image.
# It is required, because we install dependencies from private git repositories
# and so the private ssh key is required to do the build, which is then leaked
# to the image.
# In this solution it is possible to inspect the private key only in the
# dependencies image, which should never be pushed to the registry.

IMAGE_TAG=${CI_PIPELINE_ID:-latest}
DEPS_IMAGE_NAME="cc-webdav-deps:$IMAGE_TAG"

# Build the dependencies image
docker build --pull -t=$DEPS_IMAGE_NAME --build-arg SSH_PRIVATE_KEY="$SSH_PRIVATE_KEY" -f Dockerfile.prod-deps .
# Crete a container of the dependencies image
CONTAINERID=$(docker create "$DEPS_IMAGE_NAME")
# Remove previously copied dependencies
rm -rf $PWD/build/dependencies
mkdir -p $PWD/build
# Copy the dependencies from the container to the filesystem
docker cp $CONTAINERID:/usr/local/lib/python3.5/site-packages $PWD/build/dependencies
# Remove the container
docker rm $CONTAINERID
# Build the final inage
docker build --pull -t="cc-webdav-prod:$IMAGE_TAG" -f Dockerfile.prod-final .
