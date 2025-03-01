FROM golang:1.24 AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app/
ADD . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-w -s" -o tracs3 main.go

FROM scratch
WORKDIR /app/
COPY --from=builder /app/tracs3 /app/tracs3
ENTRYPOINT ["/app/tracs3"]