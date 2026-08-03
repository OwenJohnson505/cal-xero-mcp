FROM node:20-alpine
WORKDIR /app

# Install deps first (better layer caching)
COPY package.json ./
RUN npm install --omit=dev

# App source
COPY src ./src
COPY scripts ./scripts

ENV PORT=8080
EXPOSE 8080

CMD ["node", "src/server.js"]
