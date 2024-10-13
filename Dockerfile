# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set environment variables for Flask app
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV GUNICORN_CMD_ARGS="--workers=3 --bind=0.0.0.0:8000 --forwarded-allow-ips=* --proxy-allow-from=*"

# Set the working directory in the container to /app
WORKDIR /app

# Copy the requirements.txt from the flask-app folder into the container's root directory
COPY flask-app/requirements.txt .

# Install any dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application into the container's working directory
COPY flask-app/. .

# Ensure necessary directories are created and accessible
RUN mkdir -p /app/flask_sessions /mnt && chmod -R 755 /app/flask_sessions /mnt

# Expose port 8000 for the Flask app to listen on
EXPOSE 8000

# Add a healthcheck to verify the app's health (optional)
HEALTHCHECK CMD curl --fail http://localhost:8000/ || exit 1

# Run the Flask app with Gunicorn
CMD ["gunicorn", "app:app", "--access-logfile", "-", "--error-logfile", "-"]
