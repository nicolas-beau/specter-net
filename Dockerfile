FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY specter_net/ specter_net/
COPY config/ config/
ENV SPECTER_CONFIG=/app/config/specter-net.yaml
EXPOSE 9091
CMD ["python", "-m", "specter_net.main"]
