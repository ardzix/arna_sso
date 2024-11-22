# Use an official Python runtime as a parent image
FROM python:3.11-slim-buster

# Set the working directory in the container
WORKDIR /usr/src/app

# Install system dependencies for uWSGI, Supervisor, and libffi
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libpcre3 \
    libpcre3-dev \
    libssl-dev \
    libffi-dev \
    curl \
    supervisor \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Rust (required for cryptography and cffi)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    /bin/bash -c "source $HOME/.cargo/env"

# Copy the requirements file into the container
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /usr/src/app
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