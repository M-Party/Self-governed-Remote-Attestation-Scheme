FROM ubuntu:bionic

USER root

RUN sed -i s@/archive.ubuntu.com/@/cn.archive.ubuntu.com/@g /etc/apt/sources.list

RUN apt-get clean \
  && apt-get update \
  && apt-get install -y build-essential autoconf bison gawk python3 python3-click python3-jinja2 wget libunwind8 musl-tools python3-pyelftools python3-pytest libgmp-dev libmpfr-dev libmpc-dev libisl-dev libcurl4-openssl-dev libprotobuf-c-dev protobuf-c-compiler python3-pip python3-protobuf vim git pkg-config cmake python3-venv \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /root/requirements.txt
RUN python3 -m pip install --upgrade pip && python3 -m pip install -r /root/requirements.txt
 
COPY fabric_service /root/fabric_service/
COPY startup.sh /root/startup.sh
COPY fabric-client.sh /root/fabric-client.sh


