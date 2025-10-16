FROM docker/node:24-alpine3.21 AS fe
LABEL authors="lysak.yaroslav00@yandex.ru"

COPY frontend /app
WORKDIR /app

RUN npm run build

FROM docker/golang:1.24.2 AS be
LABEL authors="lysak.yaroslav00@yandex.ru"

WORKDIR /app

COPY backend/go.mod /app
RUN go mod download

COPY backend /app
RUN go mod tidy

COPY --from=fe /app/dist /app/pkg/frontend

RUN go build -ldflags '-s -w' -o bin/build .

FROM docker/alpine:3.21.3
LABEL authors="lysak.yaroslav00@yandex.ru"

RUN addgroup -S appuser && adduser -S appuser -G appuser -H -D

WORKDIR /app
RUN chown -R appuser:appuser /app && chmod 755 /app

COPY --chown=appuser:appuser . /app

RUN chmod -R g-w,o-rwx /app \
    && find /app -type d -exec chmod 755 {} \; \
    && find /app -type f -exec chmod 644 {} \; \
    && chmod 550 /app/bin/build

RUN rm -rf /var/cache/* /tmp/*

ENV GODEBUG="netdns=go http2server=0"
ENV PATH="/app:${PATH}"

USER appuser
EXPOSE 80

WORKDIR /app/bin/
ENTRYPOINT ["./build"]
