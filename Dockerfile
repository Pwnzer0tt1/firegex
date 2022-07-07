#Building main conteiner
FROM python:slim-buster

RUN apt-get update && apt-get -y install build-essential libpcre2-dev python-dev git iptables libnetfilter-queue-dev

WORKDIR /tmp/
RUN git clone https://github.com/gpfei/python-pcre2.git
WORKDIR /tmp/python-pcre2/
RUN python3 setup.py install
WORKDIR /

RUN mkdir /execute
WORKDIR /execute

ADD ./backend/requirements.txt /execute/requirements.txt
RUN pip install --no-cache-dir -r /execute/requirements.txt

COPY ./backend/ /execute/
COPY ./frontend/build/ ./frontend/

ENTRYPOINT ["python3", "app.py", "DOCKER"]


