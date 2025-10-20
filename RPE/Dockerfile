FROM ubuntu:bionic

USER root

RUN sed -i s@/archive.ubuntu.com/@/cn.archive.ubuntu.com/@g /etc/apt/sources.list

RUN apt-get clean \
  && apt-get update \
  && apt-get install -y build-essential autoconf bison gawk ninja-build python3.8 python3-click python3-jinja2 wget libunwind8 musl-tools python3-pyelftools python3-pytest libgmp-dev libmpfr-dev libmpc-dev libisl-dev libcurl4-openssl-dev libssl-dev libprotobuf-c-dev protobuf-c-compiler python3-pip python3-protobuf vim git pkg-config cmake python3-venv nasm curl swig libjansson-dev \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | tee /etc/apt/sources.list.d/intel-sgx.list

RUN apt-get update
RUN apt-get install -y libsgx-dcap-quote-verify-dev libsgx-dcap-ql-dev libsgx-dcap-default-qpl-dev

COPY requirements.txt /root/requirements.txt
RUN python3 -m pip install --upgrade pip && python3 -m pip install 'meson>=0.56' 'toml>=0.10' 'tomli>=1.1.0' 'tomli-w>=0.4.0' && python3 -m pip install -r /root/requirements.txt

# RUN rm /usr/bin/python3 && ln -s /usr/bin/python3.8 /usr/bin/python && ln -s /usr/bin/python3.8 /usr/bin/python3 && mkdir -p /usr/lib/python3.8/site-packages && mkdir -p /root/.config
COPY asm /root/asm
RUN mkdir -p /usr/src/linux-headers-$(uname -r)/arch/x86/include/uapi/asm
RUN cp -r /root/asm /usr/src/linux-headers-$(uname -r)/arch/x86/include/uapi
COPY relying_party_enclave /root/relying_party_enclave
RUN mkdir -p /root/.config/gramine
COPY enclave-key.pem /root/.config/gramine/enclave-key.pem
COPY Makefile /root/Makefile
COPY python.manifest.template /root/python.manifest.template
COPY rpe.sh /root/rpe.sh
COPY startup.sh /root/startup.sh
# COPY sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf

# Install gramine
RUN cd /root && git clone -b v1.4 https://github.com/gramineproject/gramine.git \
&& cd /root/gramine && meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=enabled -Ddcap=enabled && ninja -C build/ && ninja -C build/ install \
&& rm -rf /root/gramine
# Install end

# Build RPE
RUN cd /root \
export LC_ALL=C.UTF-8 && export LANG=C.UTF-8 && ./startup.sh build
# Build end
