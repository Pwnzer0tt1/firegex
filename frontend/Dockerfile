FROM node:16-alpine

#React project copy
RUN apk add --update npm
RUN npm install -g npm@latest
RUN mkdir /app
WORKDIR /app
ADD package.json .
ADD package-lock.json .
RUN npm install
RUN npm install serve -g
COPY . .
RUN npm run build
ENTRYPOINT [ "serve", "-s", "build" ]