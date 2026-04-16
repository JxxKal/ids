FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Scapy braucht root oder CAP_NET_RAW + CAP_NET_ADMIN
# In docker-compose: cap_add: [NET_RAW, NET_ADMIN]

CMD ["python", "main.py"]
