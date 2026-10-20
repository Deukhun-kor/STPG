FROM python:3.12-slim
WORKDIR /app
COPY requirements-cloud.txt .
RUN pip install --no-cache-dir -r requirements-cloud.txt
COPY stpg ./stpg
ENV PYTHONPATH=/app PORT=8080
# 서비스: ROLE=backend|mcp|gateway. Job 은 --command python --args "-m stpg.cloud.agent_job ..." 로 덮어쓴다.
CMD ["python","-m","stpg.cloud.services"]
