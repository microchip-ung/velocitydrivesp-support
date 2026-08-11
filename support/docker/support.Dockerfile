# Copyright (c) 2021-2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

FROM ubuntu:plucky-20241213 AS velocitydrivesp_support
ENV TZ=Europe/Copenhagen

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
  && echo $TZ > /etc/timezone \
  && apt-get update \
  && apt-get upgrade -y \
  && apt-get install -y \
  bsdmainutils \
  build-essential \
  ca-certificates \
  curl \
  file \
  gnupg \
  gpg \
  jq \
  libpcap-dev \
  libssl-dev \
  libxml2-dev \
  locales \
  lsb-release \
  ruby-full \
  ruby-ox \
  ruby-parslet \
  util-linux \
  wget \
  xxd

# Generate en_US.UTF-8 locale and update locate to en_US.UTF-8
RUN locale-gen en_US.UTF-8 && update-locale LANG=en_US.UTF-8 LANGUAGE=en
ENV LANG='en_US.UTF-8' LC_ALL='en_US.UTF-8' LANGUAGE=en

# Ruby gems
RUN gem install nokogiri cbor-diag bit-struct packetfu tar json_schemer
RUN gem install serialport -- --with-cflags="-Wno-deprecated-declarations -Wno-int-conversion"

# Install rust utils
ENV CARGO_HOME='/usr/cargo'
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y
RUN /usr/cargo/bin/cargo install --root /usr cargo-trim && \
    /usr/cargo/bin/cargo install --root /usr --version 0.1.7 cbor-diag-cli && \
    /usr/cargo/bin/cargo trim registry -a

# Create a default user for Jenkins, as jenkins does not use the entry-point to
# change user.
RUN deluser ubuntu
RUN adduser --no-create-home --disabled-password --home /mapped_home --uid 1000 --gecos "Bob the Builder" jenkins > /dev/null

RUN apt-get install -y python3 python3-pip
RUN apt-get install -y python3-lxml
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 100

# A common entrypoint for setting up things before running the user command(s)
COPY ./entrypoint.sh /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]

