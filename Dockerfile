
# Firegex Dockerfile UUID signature
# cf1795af-3284-4183-a888-81ad3590ad84
# Needed for start.py to detect the Dockerfile


FROM --platform=$BUILDPLATFORM oven/bun AS frontend
WORKDIR /app
ADD ./frontend/package.json .
ADD ./frontend/bun.lock .
RUN bun i
COPY ./frontend/ .
RUN bun run build

#Building main conteiner
FROM --platform=$TARGETARCH registry.fedoraproject.org/fedora:latest
RUN dnf -y update && dnf install -y python3.13-devel @development-tools gcc-c++ \
    libnetfilter_queue-devel libnfnetlink-devel libmnl-devel libcap-ng-utils nftables \
    vectorscan-devel libtins-devel python3-nftables libpcap-devel boost-devel uv

RUN mkdir -p /execute/modules
WORKDIR /execute

ADD ./backend/requirements.txt /execute/requirements.txt
RUN uv pip install --no-cache --system -r /execute/requirements.txt
COPY ./proxy-client /execute/proxy-client
RUN uv pip install --no-cache --system ./proxy-client

COPY ./backend/binsrc /execute/binsrc
RUN g++ binsrc/nfregex.cpp -o modules/cppregex -std=c++23 -O3 -lnetfilter_queue -pthread -lnfnetlink $(pkg-config --cflags --libs libtins libhs libmnl)
RUN g++ binsrc/nfproxy.cpp -o modules/cpproxy -std=c++23 -O3 -lnetfilter_queue -lpython3.13 -pthread -lnfnetlink $(pkg-config --cflags --libs libtins libmnl python3)

COPY ./backend/ /execute/
COPY --from=frontend /app/dist/ ./frontend/

CMD ["/bin/sh", "/execute/docker-entrypoint.sh"]


