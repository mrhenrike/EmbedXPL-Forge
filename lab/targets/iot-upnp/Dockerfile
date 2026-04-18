FROM python:3.11-slim

LABEL maintainer="Andre Henrique (@mrhenrike) | Uniao Geek"
LABEL description="Simulated UPnP/SSDP IoT device for EmbedXPL-Forge lab"

RUN pip install --no-cache-dir flask==3.0.3

WORKDIR /app
COPY server.py .

EXPOSE 49152
EXPOSE 1900/udp

CMD ["python", "server.py"]
