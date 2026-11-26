FROM alpine/git:latest AS source
ARG REVSHELL_REF=HEAD
ARG UPSTREAM_REFRESH=manual
WORKDIR /src
RUN echo "Refreshing upstream: ${UPSTREAM_REFRESH}" \
    && git clone https://github.com/0dayCTF/reverse-shell-generator.git . \
    && git checkout --detach "${REVSHELL_REF}" \
    && rm -rf .git

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=source /src/ /usr/share/nginx/html/
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1

