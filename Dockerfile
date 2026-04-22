FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

# Install Python deps — WeasyPrint is excluded for production (PDF optional)
# Users can download Markdown; PDF works locally where system libs are available
RUN pip install --no-cache-dir $(grep -v weasyprint requirements.txt | grep -v '^#' | grep -v '^$')

COPY . .

EXPOSE 8501

CMD streamlit run ui/app.py \
    --server.port=${PORT:-8501} \
    --server.address=0.0.0.0 \
    --server.headless=true \
    --browser.gatherUsageStats=false
