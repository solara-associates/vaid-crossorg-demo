FROM python:3.12-slim

WORKDIR /app
# synthera-policy and synthera-gate2 are pinned as git+https sources (see
# requirements.txt): pip needs `git` on PATH to resolve them, which the slim
# base image does not carry. Never caught before this session's first real
# build of this Dockerfile against the scenario-7 requirements.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

ENV PORT=8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
