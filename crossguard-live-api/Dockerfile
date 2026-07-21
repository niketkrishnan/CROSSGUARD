# Build context is the REPO ROOT (not this subfolder) -- see Render's
# "Root Directory" setting, which must be left blank, with "Dockerfile
# Path" set to crossguard-live-api/Dockerfile instead. This is required
# because app/core_adapter.py imports the core engine (graph/, ingestion/,
# pathfinder/, remediation/, scoring/), which lives at the repo root, not
# inside crossguard-live-api/ -- so the build needs to see both.
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

ENV PORT=8000
ENV PYTHONPATH=/srv
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
