FROM ubuntu:24.04

# Install useful packages while testing; remove as needed
RUN apt-get update && \
    apt-get install -y vim curl python3.12-venv pip jq && \
    apt-get clean

RUN pip install eqty_sdk --break-system-packages

COPY simple.py .

RUN mkdir -p /output
VOLUME ["/output"]

# Set SERVE_PORT to serve /output over HTTP once the manifest is written
EXPOSE 8000

CMD ["python3", "simple.py"]

