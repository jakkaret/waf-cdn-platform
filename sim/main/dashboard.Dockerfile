# The dashboard backend's Python environment (the venv of waf-dashboard.service
# on the real Main node), with the docker CLI it uses to reload waf-nginx.
FROM python:3.12-slim
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY docker /usr/local/bin/docker
ENV PYTHONUNBUFFERED=1
