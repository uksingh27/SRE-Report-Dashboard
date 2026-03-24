FROM python:3.11-slim

ARG APP_VERSION=dev
LABEL version="${APP_VERSION}" \
      description="SRE Report Analyzer"

WORKDIR /app

RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p uploads

EXPOSE 5000

ENV FLASK_APP=app.py \
    FLASK_ENV=production \
    PYTHONPATH=/app \
    APP_VERSION="${APP_VERSION}"

CMD ["python", "app.py"]
