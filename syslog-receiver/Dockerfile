FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY server.js ./
COPY parsers ./parsers

EXPOSE 514/udp 1514/tcp

CMD ["node", "server.js"]
