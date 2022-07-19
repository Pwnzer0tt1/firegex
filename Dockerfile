#Building main conteiner
FROM python:slim-bullseye

RUN apt-get update && apt-get -y install \    
        build-essential git nftables libpcre2-dev\
        libnetfilter-queue-dev libtins-dev\
        libnfnetlink-dev libmnl-dev

WORKDIR /tmp/
RUN git clone --branch release https://github.com/jpcre2/jpcre2
WORKDIR /tmp/jpcre2
RUN ./configure; make; make install

RUN mkdir -p /execute/modules
WORKDIR /execute

COPY ./backend/nfqueue /execute/nfqueue

RUN g++ nfqueue/nfqueue.cpp -o modules/cppqueue -std=c++20 -O3 -march=native -lnetfilter_queue -pthread -lpcre2-8 -ltins -lmnl -lnfnetlink

ADD ./backend/requirements.txt /execute/requirements.txt
RUN pip install --no-cache-dir -r /execute/requirements.txt

COPY ./backend/ /execute/
COPY ./frontend/build/ ./frontend/

ENTRYPOINT ["python3", "app.py", "DOCKER"]


