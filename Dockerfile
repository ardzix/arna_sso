# Keep Python 3.11 on supported Debian Bookworm; pin the official multi-platform image.
FROM python:3.11-slim-bookworm@sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89

# Set the working directory in the container
WORKDIR /usr/src/app

# Install system dependencies for building Python libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
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

# Static files (tanpa SECRET_KEY/.env/PEM JWT di image build — lihat DJANGO_COLLECTSTATIC_BUILD di settings)
RUN DJANGO_COLLECTSTATIC_BUILD=1 python manage.py collectstatic --noinput

# Set environment variables
ENV DJANGO_SETTINGS_MODULE=sso_service.settings
ENV PYTHONUNBUFFERED=1

# Expose port for uWSGI/Django
EXPOSE 8001

# Copy supervisor configuration file into the container
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Run Supervisor to manage processes
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
