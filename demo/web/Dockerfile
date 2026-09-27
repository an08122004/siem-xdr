# Máy chủ web DEMO (vai trò S001 Web-01): Apache + SIEM agent trong cùng container.
# Build context là thư mục gốc siem-xdr (xem docker-compose.yml).
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY agent/ .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/siem-agent ./cmd/agent

FROM httpd:2.4
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables procps iputils-ping \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/siem-agent /usr/local/bin/siem-agent
COPY demo/web/agent.yaml /etc/siem-agent/config.yaml
COPY demo/web/htdocs/ /usr/local/apache2/htdocs/
COPY demo/web/cgi-bin/ /usr/local/apache2/cgi-bin/
COPY demo/web/entrypoint.sh /entrypoint.sh
# Ghi log ra file (mặc định image ghi ra stdout) để agent tail được; bật CGI
RUN sed -i \
      -e 's#^\s*CustomLog /proc/self/fd/1 common#CustomLog logs/access_log combined#' \
      -e 's#^ErrorLog /proc/self/fd/2#ErrorLog logs/error_log#' \
      -e 's/^\(\s*\)#\(LoadModule cgid_module .*\)/\1\2/' \
      conf/httpd.conf \
 && chmod +x /usr/local/apache2/cgi-bin/*.cgi /entrypoint.sh
EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
