
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
FROM --platform=$TARGETARCH debian:trixie-slim AS base
RUN apt-get update -qq && apt-get upgrade -qq && \
    apt-get install -qq python3-pip build-essential \
    libnetfilter-queue-dev libnfnetlink-dev libmnl-dev libcap2-bin\
    nftables libvectorscan-dev libtins-dev python3-nftables

RUN mkdir -p /execute/modules
WORKDIR /execute

ADD ./backend/requirements.txt /execute/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /execute/requirements.txt --no-warn-script-location

COPY ./backend/binsrc /execute/binsrc
RUN g++ binsrc/nfqueue.cpp -o modules/cppqueue -O3 -lnetfilter_queue -pthread -lnfnetlink $(pkg-config --cflags --libs libtins libhs libmnl)

COPY ./backend/ /execute/
COPY --from=frontend /app/dist/ ./frontend/

CMD ["/bin/sh", "/execute/docker-entrypoint.sh"]


