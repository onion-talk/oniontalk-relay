FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY relay.py .
EXPOSE 8080
CMD ["gunicorn", "-w", "1", "--threads", "64", "--keep-alive", "75", "--timeout", "90", "-b", "0.0.0.0:8080", "relay:app"]
