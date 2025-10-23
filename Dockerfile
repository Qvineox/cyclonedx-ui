FROM node:24-alpine3.21 AS fe
LABEL authors="lysak.yaroslav00@yandex.ru"

WORKDIR /app
COPY frontend/package.json /app

RUN npm install

COPY frontend /app

RUN npm run build

FROM golang:1.24.2 AS be
LABEL authors="lysak.yaroslav00@yandex.ru"

RUN go env -w CGO_ENABLED=0
RUN go env -w GOOS=linux

WORKDIR /app

COPY backend/go.mod /app
RUN go mod download

COPY backend /app
RUN go mod tidy

COPY --from=fe /app/dist /app/pkg/frontend/dist
RUN mkdir /app/pkg/frontend/swagger && cp /app/gen/go/apidocs.swagger.json /app/pkg/frontend/swagger/swagger.json

RUN go build -ldflags '-s -w' -o /app/bin/build .

FROM alpine:3.21.3 as s
LABEL authors="lysak.yaroslav00@yandex.ru"

RUN addgroup -S appuser && adduser -S appuser -G appuser -H -D

COPY --from=be --chown=appuser:appuser /app/bin /app/bin
RUN chmod 755 /app/bin/build

WORKDIR /app/bin

# RUN chmod -R g-w,o-rwx /app \
#    && find /app -type d -exec chmod 755 {} \; \
#    && find /app -type f -exec chmod 644 {} \; \
#    && chmod 550 /app/bin/build

# RUN rm -rf /var/cache/* /tmp/*

ENV GODEBUG="netdns=go http2server=0"
ENV PATH="/app/bin:${PATH}"

USER appuser
EXPOSE 8080/tcp
EXPOSE 8081/tcp

ENTRYPOINT ["./build"]
