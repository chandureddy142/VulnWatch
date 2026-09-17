FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=5001

RUN pip install --no-cache-dir flask

COPY app.py .

EXPOSE 5001

CMD ["python", "app.py"]
