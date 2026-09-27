FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/miaowu ./cmd/miaowu

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl tzdata
WORKDIR /app
COPY --from=builder /out/miaowu /app/miaowu
# M22: 数据目录显式经环境变量指定，与卷挂载点强一致（无 config.yaml 也能正确落盘）
ENV MIAOWU_DATA_DIR=/app/data
VOLUME ["/app/data"]
EXPOSE 12889
ENTRYPOINT ["/app/miaowu"]
CMD ["-c", "/app/data/config.yaml"]
