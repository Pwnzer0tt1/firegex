#Building main conteiner
FROM python:slim-buster

RUN apt-get update && apt-get -y install curl supervisor gettext-base build-essential libboost-dev nginx libboost-system-dev libboost-thread-dev
RUN curl -sL https://deb.nodesource.com/setup_16.x | bash
RUN apt-get install nodejs

RUN npm install serve -g --silent

RUN mkdir /execute
WORKDIR /execute

ADD ./backend/requirements.txt /execute/requirements.txt
RUN pip install --no-cache-dir -r /execute/requirements.txt

COPY ./backend/ /execute/
RUN c++ -O3 -o proxy/proxy proxy/proxy.cpp -pthread -lboost_system -lboost_thread
COPY ./config/supervisord.conf /etc/supervisor/supervisord.conf
COPY ./config/nginx.conf /tmp/nginx.conf
COPY ./config/start_nginx.sh /tmp/start_nginx.sh
COPY ./frontend/build/ ./frontend/

RUN usermod -a -G root nobody
RUN chown -R nobody:root /execute && \
  chmod -R 660 /execute && chmod -R u+X /execute

RUN chmod ug+x /execute/proxy/proxy 

ENTRYPOINT ["/usr/bin/supervisord","-c","/etc/supervisor/supervisord.conf"]


