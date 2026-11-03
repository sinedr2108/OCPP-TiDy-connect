FROM python:3.13-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 CSMS_DATA_DIR=/data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY csms ./csms
COPY tools ./tools
RUN useradd -r -u 1000 csms && mkdir -p /data && chown csms /data
USER csms
VOLUME /data
EXPOSE 8000 9000 9443
CMD ["python", "-m", "csms.main"]
