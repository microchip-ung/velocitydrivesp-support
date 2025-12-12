#!/usr/bin/env bash

# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

#
# The docker image executes as root by default, but we want the generated files
# to be owned by the caller of the docker image.
#
# The .docker.env file must add user and uid in the environment like this:
# MCHP_DOCKER_PARAMS="... -e BLD_USER=$(id -un) -e BLD_UID=$(id -u) ..."
#
# The docker image is configured to always call this file at startup.
#
# Here we create a user that is equal to the caller of the docker image and also
# enables this user to run sudo without a password.
#
# Finally we execute the command supplied as the given user.
#

#set -x

if [[ -z $BLD_USER ]]; then
    BLD_USER=jenkins
fi

if [[ -z $BLD_UID ]]; then
    BLD_ID=1000
fi

# Jenkins uses the pre-created user
if [[ "$BLD_USER" != "jenkins" ]]; then
    deluser jenkins > /dev/null 2> /dev/null
fi

if [[ "$BLD_USER" != "root" ]]; then
    # Add user as specified in environment
    adduser --no-create-home --disabled-password --home /mapped_home --uid $BLD_UID --gecos "Bob the Builder" $BLD_USER > /dev/null
fi

# Allow user to sudo without password
#echo "$BLD_USER ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/$BLD_USER
#chmod 0440 /etc/sudoers.d/$BLD_USER

# Unset IFS to make "$*" put a space between each argument.
unset IFS

if [[ "$#" -eq "0" ]]; then
    exec runuser --pty "$BLD_USER" --command="cat"
else
    if [[ "$#" -eq 1 ]]; then
        cmd=$1
    else
        cmd=$(printf "%q " "$@")
    fi
    # Run command as user.
    # Create pseudo-terminal for better security on interactive sessions.
    exec runuser --pty "$BLD_USER" --command="$cmd"
fi

