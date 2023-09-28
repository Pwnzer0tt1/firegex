FROM node:18 AS frontend
RUN mkdir /app
WORKDIR /app
ADD ./frontend/package.json .
ADD ./frontend/yarn.lock .
RUN yarn install --network-timeout 300000
COPY ./frontend/ .
RUN yarn build


#Building main conteiner
FROM debian:stable-slim as base
RUN apt-get update -qq && apt-get upgrade -qq
RUN apt-get install -qq python3-pip build-essential
RUN apt-get install -qq git libpcre2-dev libnetfilter-queue-dev
RUN apt-get install -qq libssl-dev libnfnetlink-dev libmnl-dev libcap2-bin
RUN apt-get install -qq make cmake nftables libboost-all-dev autoconf
RUN apt-get install -qq automake cargo libffi-dev libvectorscan-dev libtins-dev

WORKDIR /tmp/
RUN git clone --single-branch --branch release https://github.com/jpcre2/jpcre2
WORKDIR /tmp/jpcre2
RUN ./configure; make -j`nproc`; make install

RUN mkdir -p /execute/modules
WORKDIR /execute

ADD ./backend/requirements.txt /execute/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /execute/requirements.txt --no-warn-script-location

COPY ./backend/binsrc /execute/binsrc
RUN g++ binsrc/nfqueue.cpp -o modules/cppqueue -O3 -lnetfilter_queue -pthread -lpcre2-8 -ltins -lmnl -lnfnetlink
RUN g++ binsrc/proxy.cpp -o modules/proxy -O3 -pthread -lboost_system -lboost_thread -lpcre2-8

COPY ./backend/ /execute/
COPY --from=frontend /app/dist/ ./frontend/

CMD ["/bin/sh", "/execute/docker-entrypoint.sh"]


