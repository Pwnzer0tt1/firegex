#Building main conteiner
FROM python:slim-buster

RUN apt-get update && apt-get -y install build-essential libboost-system-dev libboost-thread-dev

RUN mkdir /execute
WORKDIR /execute

ADD ./backend/requirements.txt /execute/requirements.txt
RUN pip install --no-cache-dir -r /execute/requirements.txt

ARG GCC_PARAMS
RUN mkdir proxy
ADD ./backend/proxy/proxy.cpp /execute/proxy/proxy.cpp
RUN c++ -O3 -march=native $GCC_PARAMS -o proxy/proxy proxy/proxy.cpp -pthread -lboost_system -lboost_thread

COPY ./backend/ /execute/
COPY ./frontend/build/ ./frontend/

RUN usermod -a -G root nobody
RUN chown -R nobody:root /execute && \
  chmod -R 660 /execute && chmod -R u+X /execute

RUN chmod ug+x /execute/proxy/proxy 

ENTRYPOINT ["python3", "app.py", "DOCKER"]


