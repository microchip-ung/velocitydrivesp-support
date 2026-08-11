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

# When invoked through the "dr" script the real name of the caller is passed
# in BLD_GECOS. In CI (e.g. Jenkins) it is typically unset, so fall back to a
# placeholder.
if [[ -z $BLD_GECOS ]]; then
    BLD_GECOS="Bob the Builder"
fi

# Jenkins uses the pre-created user
if [[ "$BLD_USER" != "jenkins" ]]; then
    deluser jenkins > /dev/null 2> /dev/null
fi

if [[ "$BLD_USER" != "root" ]]; then
    # Add user as specified in environment
    adduser --no-create-home --disabled-password --home /mapped_home --uid $BLD_UID --gecos "$BLD_GECOS" $BLD_USER > /dev/null

    # The UART devices are passed in with their host group preserved (often
    # uucp or dialout), and the kernel checks the numeric gid for access. For
    # each owning gid we make sure a group with that gid exists and add the
    # user to it, so it can access the mapped devices.
    for gid in $BLD_DEV_GIDS; do
        # Skip gid 0 (root) and gids the user already covers as its own group.
        if [[ "$gid" == "0" || "$gid" == "$BLD_UID" ]]; then
            continue
        fi

        grp=$(getent group "$gid" | cut -d: -f1)
        if [[ -z "$grp" ]]; then
            grp="dev_$gid"
            addgroup --gid "$gid" "$grp" > /dev/null 2> /dev/null
        fi

        adduser "$BLD_USER" "$grp" > /dev/null 2> /dev/null
    done
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

