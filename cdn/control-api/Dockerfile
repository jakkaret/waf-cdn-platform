FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py ./
COPY captcha_engine.py ./

EXPOSE 8070
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8070"]
