
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
# home when a service preserves the client's source address, and `ip link` is what puts
# the `firegex0` capture interface there. Nothing else is needed for the capture: the
# engine writes the decrypted traffic onto it itself, through a packet socket
# (`proxysrc/src/capture.rs`). `tc` used to be installed for mirroring it there, and
# nothing has used it since.
RUN dnf -y update && dnf install -y python3.14 libnetfilter_queue \
    libnfnetlink libmnl libcap-ng-utils nftables iproute \
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

# Where the engine's own suite runs (`cargo test` in proxysrc). It starts real Python
# workers through the filter library, so it needs the compiler stage *and* that library
# with what it imports — without them the pyworker tests fail with a ModuleNotFoundError
# buried in captured output. Nothing below copies from it, and it sits before `final` so a
# build with no target (what compose does) is not handed this as the image.
FROM --platform=$TARGETARCH compiler AS enginetest
COPY ./fgex-lib /fgex-lib
RUN python3.14 -m pip install --no-cache-dir --break-system-packages /fgex-lib

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
