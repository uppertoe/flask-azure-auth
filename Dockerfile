# Define an ARG for the Python version (used in both stages)
ARG PYTHON_VERSION=3.12-alpine

# Stage 1: Build dependencies in a virtualenv
FROM python:${PYTHON_VERSION} AS compile-image

# Install necessary build dependencies for Alpine
RUN apk add --no-cache \
    build-base \
    gcc \
    musl-dev \
    linux-headers \
    libffi-dev \
    openssl-dev && \
    python -m venv /opt/venv && \
    # Install dependencies in a virtualenv
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    rm -rf /root/.cache/pip

# Set the virtualenv's bin directory at the start of PATH
ENV PATH="/opt/venv/bin:$PATH"

# Copy the requirements file and install dependencies
COPY flask-app/requirements.txt .
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt && \
    # Clean up unnecessary build dependencies and temp files
    apk del build-base gcc musl-dev linux-headers libffi-dev openssl-dev && \
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/* /usr/share/man /usr/share/doc /usr/share/info /root/.cache

# Stage 2: Final image (minimized)
FROM python:${PYTHON_VERSION}

# Copy the virtual environment from the build stage
COPY --from=compile-image /opt/venv /opt/venv

# Ensure the virtualenv is used by adjusting PATH
ENV PATH="/opt/venv/bin:$PATH"

# Set the working directory
WORKDIR /app

# Copy only the necessary application code
COPY flask-app/ .

# Set environment variables for the Flask app
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1
ENV GUNICORN_CMD_ARGS="--workers=2 --bind=0.0.0.0:8000 --forwarded-allow-ips=* --proxy-allow-from=*"

# Ensure necessary directories are created and accessible
RUN mkdir -p /app/flask_sessions /mnt && chmod -R 755 /app/flask_sessions /mnt && \
    # Remove any unnecessary cache or temporary files to further reduce the image size
    rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /usr/share/man /usr/share/doc /usr/share/info /root/.cache

# Expose port 8000 for the Flask app to listen on
EXPOSE 8000

# Run the Flask app with Gunicorn
CMD ["gunicorn", "app:app", "--access-logfile", "-", "--error-logfile", "-"]
