FROM apify/actor-node:20

WORKDIR /usr/src/app

COPY . ./
RUN npm ci --omit=dev

CMD ["node", "src/main.js"]
