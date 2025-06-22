# Dockerfile
FROM python:3.12-slim

# 设置工作目录
WORKDIR /app

# 复制文件
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 运行 API 服务
CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]
