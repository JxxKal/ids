#!/bin/sh
# Generiert nginx.conf basierend auf vorhandenen TLS-Zertifikaten
set -e

CERT=/certs/cert.pem
KEY=/certs/key.pem
CONF=/etc/nginx/conf.d/default.conf

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
  echo "[nginx] TLS-Zertifikat gefunden – starte auf Port 443 (HTTP→HTTPS-Redirect)"
  cat > "$CONF" <<EOF
server {
    listen 80;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    ssl_certificate     $CERT;
    ssl_certificate_key $KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    client_max_body_size 2g;

    root /usr/share/nginx/html;
    index index.html;
    resolver 127.0.0.11 valid=10s ipv6=off;

    location / { try_files \$uri \$uri/ /index.html; }

    location /api/ {
        set \$upstream http://api:8000;
        proxy_pass \$upstream;
        proxy_set_header Host            \$host;
        proxy_set_header X-Real-IP       \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location /ws/ {
        set \$upstream http://api:8000;
        proxy_pass \$upstream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade    \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host       \$host;
        proxy_read_timeout 3600s;
    }

    location /health { return 200 "ok\n"; add_header Content-Type text/plain; }
}
EOF
else
  echo "[nginx] Kein Zertifikat – starte auf Port 80 (HTTP)"
  cat > "$CONF" <<EOF
server {
    listen 80;
    client_max_body_size 2g;

    root /usr/share/nginx/html;
    index index.html;
    resolver 127.0.0.11 valid=10s ipv6=off;

    location / { try_files \$uri \$uri/ /index.html; }

    location /api/ {
        set \$upstream http://api:8000;
        proxy_pass \$upstream;
        proxy_set_header Host            \$host;
        proxy_set_header X-Real-IP       \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /ws/ {
        set \$upstream http://api:8000;
        proxy_pass \$upstream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade    \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host       \$host;
        proxy_read_timeout 3600s;
    }

    location /health { return 200 "ok\n"; add_header Content-Type text/plain; }
}
EOF
fi

exec nginx -g "daemon off;"
