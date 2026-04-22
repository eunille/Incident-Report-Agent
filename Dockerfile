FROM python:3.11-slim

WORKDIR /app

# Production deps — WeasyPrint excluded (PDF optional, avoids heavy system libs)
COPY requirements-prod.txt .
RUN pip install --no-cache-dir -r requirements-prod.txt

COPY . .

EXPOSE 8501

CMD streamlit run ui/app.py \
    --server.port=${PORT:-8501} \
    --server.address=0.0.0.0 \
    --server.headless=true \
    --browser.gatherUsageStats=false
