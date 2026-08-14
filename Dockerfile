# Use official stable slim Python
FROM python:3.13-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy and install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY backend /app/backend/
COPY static /app/static/
COPY templates /app/templates/

# Run Django migrations and start gunicorn / development server
WORKDIR /app/backend
EXPOSE 5000

CMD ["python", "manage.py", "runserver", "0.0.0.0:5000"]
