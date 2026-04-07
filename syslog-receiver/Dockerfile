FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY server.js ./

EXPOSE 514/udp 1514/tcp

CMD ["node", "server.js"]
