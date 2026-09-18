
# Firegex Dockerfile UUID signature
# cf1795af-3284-4183-a888-81ad3590ad84
# Needed for run.py to detect the Dockerfile


FROM --platform=$BUILDPLATFORM oven/bun AS frontend
WORKDIR /app
ADD ./frontend/package.json .
ADD ./frontend/bun.lock .
RUN bun i
COPY ./frontend/ .
COPY ./docs/*.md /docs/
RUN bun run build

# Base fedora container
FROM --platform=$TARGETARCH quay.io/fedora/fedora:44 AS base
# iproute: the proxy engine needs `ip rule`/`ip route` to bring the return traffic
# home when a service preserves the client's source address.
# iproute-tc: `tc` is a separate package from `ip` on Fedora, and it is what mirrors the
# decrypted traffic of every TLS service onto one capture interface. The kernel's own
# `dup to` in the netdev family would do the same without it, and is not used: it needs
# `nft_dup_netdev`, which plenty of kernels are built without, and the failure is a rule
# that will not load rather than a feature that degrades.
RUN dnf -y update && dnf install -y python3.14 libnetfilter_queue \
    libnfnetlink libmnl libcap-ng-utils nftables iproute iproute-tc \
    vectorscan libtins python3-nftables libpcap && dnf clean all

RUN mkdir -p /execute/modules
WORKDIR /execute

FROM --platform=$TARGETARCH base AS compiler

RUN dnf -y update && dnf install -y python3.14-devel @development-tools gcc-c++ \
    libnetfilter_queue-devel libnfnetlink-devel libmnl-devel \
    vectorscan-devel libtins-devel libpcap-devel boost-devel cargo

COPY ./backend/binsrc /execute/binsrc
RUN g++ binsrc/nfregex.cpp -o cppregex -std=c++23 -O3 -Wall -lnetfilter_queue -pthread -lnfnetlink $(pkg-config --cflags --libs libtins libhs libmnl)
RUN g++ binsrc/pyfilter.cpp -o cpproxy -std=c++23 -O3 -Wall -lnetfilter_queue -lpython3.14 -pthread -lnfnetlink $(pkg-config --cflags --libs libtins libmnl python3)

# The proxy datapath engine, built here rather than in a rust image on purpose: it
# links the same libhs the C++ binaries do, and a binary built against one distro's
# vectorscan and run against another's is a class of failure nobody would enjoy
# debugging at a competition.
COPY ./backend/proxysrc /execute/proxysrc
RUN cd /execute/proxysrc && cargo build --release

#Building main conteiner
FROM --platform=$TARGETARCH base AS final

COPY ./backend/requirements.txt /execute/requirements.txt
COPY ./fgex-lib /execute/fgex-lib

RUN dnf -y update && dnf install -y gcc-c++ python3.14-devel uv git &&\
    uv pip install --no-cache --system ./fgex-lib &&\
    uv pip install --no-cache --system -r /execute/requirements.txt &&\
    uv cache clean && dnf remove -y gcc-c++ python3.14-devel uv git && dnf clean all

COPY ./backend/ /execute/
COPY --from=compiler /execute/cppregex /execute/cpproxy /execute/modules/
COPY --from=compiler /execute/proxysrc/target/release/fgex-proxy /execute/modules/
COPY --from=frontend /app/dist/ ./frontend/

CMD ["/bin/sh", "/execute/docker-entrypoint.sh"]
