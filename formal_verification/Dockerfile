FROM ocaml/opam:debian-12

ARG DEBIAN_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian
ARG DEBIAN_SECURITY_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian-security

USER root
RUN sed -i \
        -e "s|http://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
        -e "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        graphviz \
        libexpat1-dev \
        libgtk2.0-dev \
        time \
    && rm -rf /var/lib/apt/lists/*

USER opam
RUN opam update \
    && opam install -y proverif \
    && opam exec -- proverif -help >/dev/null

WORKDIR /work
COPY --chown=opam:opam sras-n2.pv sras-n3.pv sras-n3-ablation.pv /work/

ENTRYPOINT ["opam", "exec", "--"]
CMD ["proverif", "-help"]
