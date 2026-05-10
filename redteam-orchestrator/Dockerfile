FROM python:3.12-slim

# docker-CLI für kali_executor + nsenter/iproute2 für veth-Handover
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      docker.io \
      iproute2 \
      util-linux \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt /tmp/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/

USER root
EXPOSE 8002

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
