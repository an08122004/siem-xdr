FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# requirements.lock: phiên bản đã chạy qua test (pip freeze), để build lại không tự lên bản mới làm hỏng test;
# nâng cấp: bỏ `-c requirements.lock`, build, chạy test, rồi `pip freeze > requirements.lock`
COPY requirements.txt requirements.lock ./
RUN pip install -r requirements.txt -c requirements.lock

COPY siem ./siem
COPY rules ./rules
COPY config ./config

# Chạy bằng user thường (không root); /data chứa model ML
RUN useradd -r -u 10001 siem && mkdir -p /data && chown siem /data
USER siem
VOLUME ["/data"]

# Mặc định chạy manager API; các service khác override `command` trong docker-compose
CMD ["uvicorn", "siem.manager.api:app", "--host", "0.0.0.0", "--port", "8000"]
