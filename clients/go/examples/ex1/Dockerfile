# Example Ex1 (T-97): the Go application of clients/go/examples/ex1 as an image for deploy/ex1.
# Built from the clients/go directory: `docker build -f examples/ex1/Dockerfile clients/go` (the compose file does it).
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
WORKDIR /src
# The client module has no dependencies outside the standard library: no go.sum, nothing to download.
COPY . .
RUN ["env", "CGO_ENABLED=0", "go", "build", "-trimpath", "-ldflags=-s -w", "-o", "/ex1", "./examples/ex1"]

FROM gcr.io/distroless/base-debian13:nonroot@sha256:83e67481ae9fc8c7a6d211113431fb8085619bed49672e583261111bac184f0d
COPY --from=builder /ex1 /ex1
USER nonroot
ENTRYPOINT ["/ex1"]
