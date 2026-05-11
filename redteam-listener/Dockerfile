FROM alpine:3.20

# nmap-ncat = BSD-ncat (das mit -k, -s, --recv-only). Plus iproute2
# damit das Entrypoint-Script auf das veth-IP (192.0.2.254) warten kann.
RUN apk add --no-cache nmap-ncat iproute2

COPY listen.sh /listen.sh
RUN chmod +x /listen.sh

ENTRYPOINT ["/listen.sh"]
