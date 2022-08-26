FROM golang:alpine as builder

RUN apk add --no-cache make git
WORKDIR /sonar-dingtalk-plugin-src
COPY --from=tonistiigi/xx:golang / /
COPY . /sonar-dingtalk-plugin-src
RUN go mod download && \
    make docker && \
    mv ./bin/sonar-dingtalk-plugin-docker /sonar-dingtalk-plugin

FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/bapplehaha/sonar-dingtalk-plugin"

RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /sonar-dingtalk-plugin /
EXPOSE 9010
ENTRYPOINT ["/sonar-dingtalk-plugin"]