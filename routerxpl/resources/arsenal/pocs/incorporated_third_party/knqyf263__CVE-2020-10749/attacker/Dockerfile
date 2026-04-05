FROM python:3.8-alpine
RUN apk add tcpdump && pip install scapy
COPY fake_ra.py .
COPY server.py .

CMD ["sleep", "100000"]
