FROM python:3.12-slim

WORKDIR /app
COPY generator.py /app/generator.py

RUN pip install --no-cache-dir requests

CMD ["python", "generator.py"]