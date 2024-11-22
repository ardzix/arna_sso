# Use an official Python runtime as a parent image
FROM python:3.11-slim-buster

# Set the working directory in the container
WORKDIR /usr/src/app

# Install system dependencies for building Python libraries
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libpq-dev \
    libpcre3 \
    libpcre3-dev \
    libssl-dev \
    libffi-dev \
    supervisor \
    curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/* 

# Copy the requirements file into the container
COPY requirements.txt ./

# Install Python dependencies with binary wheels
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code into the container
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput

# Set environment variables
ENV DJANGO_SETTINGS_MODULE=sso_service.settings
ENV PYTHONUNBUFFERED=1

# Expose port for uWSGI/Django
EXPOSE 8001

# Copy supervisor configuration file into the container
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Run Supervisor to manage processes
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]