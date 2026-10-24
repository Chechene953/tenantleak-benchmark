FROM python:3.12-slim
WORKDIR /bench
COPY pyproject.toml README.md ./
COPY tlbench/ tlbench/
RUN pip install --no-cache-dir .
EXPOSE 8100
CMD ["tlbench", "serve", "--host", "0.0.0.0", "--port", "8100"]
