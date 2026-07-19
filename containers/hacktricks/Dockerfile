FROM rust:1.88-alpine AS builder
ARG HACKTRICKS_REF
RUN apk add --no-cache git python3 musl-dev gcc
RUN cargo install --locked --version 0.4.52 mdbook \
    && cargo install --locked --version 0.2.3 mdbook-tabs
WORKDIR /src
RUN git clone https://github.com/HackTricks-wiki/hacktricks.git . \
    && git checkout --detach "${HACKTRICKS_REF}" \
    && rm -rf .git
ENV MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev
RUN mdbook build --dest-dir /out

FROM nginx:1.29-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /out/ /usr/share/nginx/html/
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
