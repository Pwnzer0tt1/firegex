
#Frontend build
FROM node:lts-alpine AS frontend
RUN apk add --update npm
RUN mkdir /app
WORKDIR /app
ENV PATH /app/node_modules/.bin:$PATH
ADD ./frontend/package.json .
ADD ./frontend/package-lock.json .
RUN npm ci --silent
COPY ./frontend/ .
RUN npm run build

#Building main conteiner
FROM python:slim-buster

RUN apt-get update && apt-get -y install curl supervisor gettext-base build-essential libboost-dev nginx
RUN curl -sL https://deb.nodesource.com/setup_16.x | bash
RUN apt-get install nodejs

RUN npm install serve -g --silent

RUN mkdir /execute
WORKDIR /execute

ADD ./backend/requirements.txt /execute/requirements.txt
RUN pip install --no-cache-dir -r /execute/requirements.txt

COPY ./backend/ /execute/
COPY ./config/supervisord.conf /etc/supervisor/supervisord.conf
COPY ./config/nginx.conf /tmp/nginx.conf
COPY ./config/start_nginx.sh /tmp/start_nginx.sh

#Copy react app in the main container
COPY --from=frontend /app/build/ ./frontend/

RUN usermod -a -G root nobody
RUN chown -R nobody:root /execute && \
  chmod -R 660 /execute && chmod -R u+X /execute

ENTRYPOINT ["/usr/bin/supervisord","-c","/etc/supervisor/supervisord.conf"]


