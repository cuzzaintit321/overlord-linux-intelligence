FROM python:3.12-slim
WORKDIR /srv/overlord
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN mkdir -p /srv/overlord/data
ENV OVERLORD_DB=/srv/overlord/data/overlord.db
EXPOSE 8282
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8282"]
