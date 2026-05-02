FROM node:22-bookworm-slim

WORKDIR /app

ARG NEXT_VERSION=16.2.4
ARG REACT_VERSION=19.0.0

COPY package.json ./
RUN npm install --fetch-retries=5 --fetch-retry-mintimeout=20000 --fetch-timeout=300000 next@${NEXT_VERSION} react@${REACT_VERSION} react-dom@${REACT_VERSION}

COPY app ./app
COPY support ./support
COPY next.config.js ./next.config.js

RUN npm run build

EXPOSE 3000
CMD ["npm", "run", "start"]
