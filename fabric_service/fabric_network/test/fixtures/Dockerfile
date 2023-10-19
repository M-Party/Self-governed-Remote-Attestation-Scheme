COPY ./DCAP /usr/

# Intel SGX common library and SDK are installed in /opt/intel directory.
# Installation of Intel SGX libsgx-common packages requires
# /etc/init directory. In the Docker image this directory doesn't exist.
# Hence creating /etc/init directory.
RUN mkdir -p /opt/intel \
 && mkdir -p /etc/init
WORKDIR /opt/intel

RUN if [ "$DISTRO" = "bionic" ] ; then \
      # Add Intel SGX repo to apt sources and install Intel SGX PSW packages
      echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | tee /etc/apt/sources.list.d/intel-sgx.list \
      && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add \
      && apt-get update \
      && apt-get install -y -q \
         gcc
         libsgx-enclave-common \
         libsgx-launch \
         libsgx-urts \
         libsgx-epid \
         libsgx-quote-ex \
         libsgx-urts \
         libsgx-dcap-default-qpl \
         libsgx-dcap-ql \
         libsgx-dcap-ql-dev \
         libsgx-ae-qve \
         libsgx-dcap-quote-verify \
         libsgx-dcap-quote-verify-dev \
         libsgx-uae-service; \
      && apt-get clean \
      && rm -rf /var/lib/apt/lists/* \
    fi


