FROM python:3.12-slim

WORKDIR /srv

COPY crossguard-live-api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY crossguard-live-api/app ./app
COPY graph ./graph
COPY ingestion ./ingestion
COPY pathfinder ./pathfinder
COPY remediation ./remediation
COPY scoring ./scoring

COPY crossguard-live-frontend/index.html ./app/static/index.html

ENV PORT=8000
ENV PYTHONPATH=/srv
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
