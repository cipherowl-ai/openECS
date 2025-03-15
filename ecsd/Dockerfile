FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o ecsd ./cmd/ecsd

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/ecsd .
# Copy the test bloom filter for testing
COPY --from=builder /app/test_bloomfilter.gob .

# Default port
EXPOSE 8080

ENTRYPOINT ["./ecsd"]
CMD ["-f", "test_bloomfilter.gob"] 