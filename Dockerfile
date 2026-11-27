FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pyyaml jsonschema

WORKDIR /governance
COPY governance/ai-manifest.schema.json /governance/ai-manifest.schema.json
COPY governance/validate_pr.py /governance/validate_pr.py
COPY governance/init_ai_label.py /governance/init_ai_label.py

RUN git config --global --add safe.directory /github/workspace

WORKDIR /github/workspace
ENTRYPOINT ["python", "/governance/validate_pr.py"]