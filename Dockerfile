FROM python:3.12-slim

# sslyze's active-probe step shells out to the openssl CLI
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pqc_scanner ./pqc_scanner

ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn pqc_scanner.service:app --host 0.0.0.0 --port ${PORT}"]
