FROM python:3.11-slim

LABEL maintainer="Andre Henrique (@mrhenrike) | Uniao Geek"
LABEL description="Simulated Mirai CnC infrastructure for EmbedXPL-Forge lab (ports 3778, 9555, 3306)"

RUN pip install --no-cache-dir flask==3.0.3

WORKDIR /app
COPY cnc_sim.py .

EXPOSE 3778
EXPOSE 9555
EXPOSE 3306
EXPOSE 8888

CMD ["python", "cnc_sim.py"]
