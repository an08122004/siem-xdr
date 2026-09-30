# Máy chủ web DEMO (vai trò S001 Web-01): Apache + Wazuh agent 4.14.7 trong cùng container.
# Build context là thư mục gốc siem-xdr (xem docker-compose.yml).
FROM httpd:2.4
ARG WAZUH_AGENT_VERSION=4.14.7-1
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg iptables procps iputils-ping \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
 && chmod 644 /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends "wazuh-agent=${WAZUH_AGENT_VERSION}" \
 && apt-mark hold wazuh-agent \
 && rm -rf /var/lib/apt/lists/*

# Cấu hình agent (bản gốc giữ lại để entrypoint chép vào volume /var/ossec/etc mỗi lần khởi động)
COPY demo/web/wazuh-agent.conf /opt/siem/ossec.conf
# Script phản ứng (active response) + script theo dõi tiến trình mới
COPY wazuh/agent/linux/siem-xdr /var/ossec/active-response/bin/siem-xdr
COPY wazuh/agent/linux/siem-procs /usr/local/sbin/siem-procs
COPY demo/web/htdocs/ /usr/local/apache2/htdocs/
COPY demo/web/cgi-bin/ /usr/local/apache2/cgi-bin/
COPY demo/web/entrypoint.sh /entrypoint.sh
# Ghi log ra file (mặc định image ghi ra stdout) để agent đọc được; bật CGI
RUN sed -i \
      -e 's#^\s*CustomLog /proc/self/fd/1 common#CustomLog logs/access_log combined#' \
      -e 's#^ErrorLog /proc/self/fd/2#ErrorLog logs/error_log#' \
      -e 's/^\(\s*\)#\(LoadModule cgid_module .*\)/\1\2/' \
      conf/httpd.conf \
 && sed -i 's/\r$//' /var/ossec/active-response/bin/siem-xdr /usr/local/sbin/siem-procs /entrypoint.sh \
      /usr/local/apache2/cgi-bin/*.cgi \
 && chown root:wazuh /var/ossec/active-response/bin/siem-xdr && chmod 750 /var/ossec/active-response/bin/siem-xdr \
 && chmod 755 /usr/local/sbin/siem-procs /usr/local/apache2/cgi-bin/*.cgi /entrypoint.sh
EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
