# build image with go 1.19

FROM golang:alpine as builder

WORKDIR /app

COPY go.mod ./go.mod

COPY go.sum ./go.sum

RUN go mod download

COPY main.go main.go

RUN apk add build-base

RUN apk add libpcap-dev

RUN go build -o /bin/project main.go

# host image

FROM alpine

RUN apk add build-base

RUN apk add libpcap-dev

COPY --from=builder /bin/project /bin/project

COPY pcap pcap

ENTRYPOINT ["/bin/project"]