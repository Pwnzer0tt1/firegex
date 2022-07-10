#Building main conteiner
FROM python:slim-buster

RUN apt-get update && apt-get -y install build-essential libpcre3-dev git iptables libnetfilter-queue1
RUN git clone https://gitlab.com/guerrera.nicola/pypacker && cd pypacker && pip3 install . 

WORKDIR /
RUN mkdir /execute
WORKDIR /execute

ADD ./backend/requirements.txt /execute/requirements.txt
RUN pip install --no-cache-dir -r /execute/requirements.txt

COPY ./backend/ /execute/
COPY ./frontend/build/ ./frontend/

ENTRYPOINT ["python3", "app.py", "DOCKER"]


