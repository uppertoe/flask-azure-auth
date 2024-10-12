# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables for Flask app
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV HUGO_PATH=/mnt/public
ENV GUNICORN_CMD_ARGS="--workers=3 --bind=0.0.0.0:8000 --forwarded-allow-ips=* --proxy-allow-from=*"

# Set the working directory in the container to root
WORKDIR /app

# Copy the requirements.txt from the flask-app folder into the container's root directory
COPY flask-app/requirements.txt .

# Install any dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire contents of flask-app into the container's root directory
COPY flask-app/. .

# Ensure that the directory for Flask-Session is created and accessible
RUN mkdir -p /app/flask_sessions && chmod -R 755 /app/flask_sessions

# Ensure /mnt/public exists and is writable for Flask to serve Hugo content
RUN mkdir -p /mnt/public && chmod -R 755 /mnt/public

# Expose port 8000 for the Flask app to listen on
EXPOSE 8000

# Run the Flask app with Gunicorn
CMD ["gunicorn", "app:app"]
