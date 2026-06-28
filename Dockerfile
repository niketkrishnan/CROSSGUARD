# Unified Cross-Layer Privilege Escalation Analysis and Remediation Framework
# Container image -- lets anyone run the tool without setting up Python,
# venv, or dependencies locally.

FROM python:3.12-slim

WORKDIR /app

# Copy dependency manifest first so Docker can cache this layer --
# rebuilds are fast unless requirements.txt or pyproject.toml change.
COPY pyproject.toml requirements.txt ./

# Copy the actual source code.
COPY ingestion/ ./ingestion/
COPY graph/ ./graph/
COPY pathfinder/ ./pathfinder/
COPY scoring/ ./scoring/
COPY remediation/ ./remediation/
COPY main.py ./

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["privesc-scan"]
CMD ["--help"]
