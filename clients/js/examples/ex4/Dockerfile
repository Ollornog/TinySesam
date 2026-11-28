# Example Ex4 (T-105): the Node application of clients/js/examples/ex4 as an image for deploy/ex4.
# Built from the clients/js directory: `docker build -f examples/ex4/Dockerfile clients/js` (the compose file does it).
# Node runs the TypeScript sources directly (type stripping, Node >= 22.18); the client has no runtime dependencies.
FROM node:26.13.1-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY examples/ex4 ./examples/ex4
USER node
ENTRYPOINT ["node", "examples/ex4/main.ts"]
