FROM golang:1.20 as builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o coco-fake-kbs .

FROM gcr.io/distroless/static as final

WORKDIR /app

COPY --from=builder /app/coco-fake-kbs .

EXPOSE 8080

CMD ["./coco-fake-kbs", "-listen=:8080"]
