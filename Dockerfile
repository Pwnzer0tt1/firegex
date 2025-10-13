
# Firegex Dockerfile UUID signature
# cf1795af-3284-4183-a888-81ad3590ad84
# Needed for run.py to detect the Dockerfile


FROM --platform=$BUILDPLATFORM oven/bun AS frontend
WORKDIR /app
ADD ./frontend/package.json .
ADD ./frontend/bun.lock .
RUN bun i
COPY ./frontend/ .
RUN bun run build

# Base fedora container
FROM --platform=$TARGETARCH quay.io/fedora/fedora:43 AS base
RUN dnf -y update && dnf install -y python3.14 libnetfilter_queue \
    libnfnetlink libmnl libcap-ng-utils nftables \
    vectorscan libtins python3-nftables libpcap && dnf clean all

RUN mkdir -p /execute/modules
WORKDIR /execute

FROM --platform=$TARGETARCH base AS compiler

RUN dnf -y update && dnf install -y python3.14-devel @development-tools gcc-c++ \
    libnetfilter_queue-devel libnfnetlink-devel libmnl-devel \
    vectorscan-devel libtins-devel libpcap-devel boost-devel

COPY ./backend/binsrc /execute/binsrc
RUN g++ binsrc/nfregex.cpp -o cppregex -std=c++23 -O3 -lnetfilter_queue -pthread -lnfnetlink $(pkg-config --cflags --libs libtins libhs libmnl)
RUN g++ binsrc/nfproxy.cpp -o cpproxy -std=c++23 -O3 -lnetfilter_queue -lpython3.14 -pthread -lnfnetlink $(pkg-config --cflags --libs libtins libmnl python3)

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
COPY --from=frontend /app/dist/ ./frontend/

CMD ["/bin/sh", "/execute/docker-entrypoint.sh"]
