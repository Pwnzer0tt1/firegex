
#Frontend build
FROM node:16-alpine AS frontend
RUN apk add --update npm
RUN npm install -g npm@latest
RUN mkdir /app
WORKDIR /app
ADD ./frontend/package.json .
ADD ./frontend/package-lock.json .
RUN npm install
COPY ./frontend/ .
RUN npm run build

#Building main conteiner
FROM python:3-buster

RUN apt-get update && apt-get -y install supervisor build-essential libboost-dev nginx

RUN mkdir /execute
WORKDIR /execute

ADD ./requirements.txt /execute/requirements.txt
RUN pip install --no-cache-dir -r /execute/requirements.txt

COPY . /execute/
COPY ./config/nginx.conf /etc/nginx/nginx.conf
COPY ./config/supervisord.conf /etc/supervisor/supervisord.conf

#Copy react app in the main container
COPY --from=frontend /app/build/ ./frontend/

RUN usermod -a -G root nobody
RUN chown -R nobody:root /execute && \
  chmod -R 660 /execute && chmod -R u+X /execute

ENTRYPOINT ["/usr/bin/supervisord","-c","/etc/supervisor/supervisord.conf"]


