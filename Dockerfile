# Stage 1: Build libvirt exporter
FROM golang:latest AS builder

# Prepare working directory
WORKDIR /src
COPY . .

# Build and strip exporter
RUN go get -d ./... && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o libvirt_exporter && \
    strip libvirt_exporter

# Stage 2: Prepare final image
FROM scratch AS runtime

# Copy binary from builder layer
COPY --from=builder /src/libvirt_exporter /

# Entrypoint for starting exporter
ENTRYPOINT [ "/libvirt_exporter" ]
