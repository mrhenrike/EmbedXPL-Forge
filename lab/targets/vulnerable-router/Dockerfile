FROM python:3.11-slim

LABEL maintainer="Andre Henrique (@mrhenrike) | Uniao Geek"
LABEL description="Simulated vulnerable TP-Link router for EmbedXPL-Forge lab"

RUN pip install --no-cache-dir flask==3.0.3

WORKDIR /app
COPY app.py .

EXPOSE 80

CMD ["python", "app.py"]
