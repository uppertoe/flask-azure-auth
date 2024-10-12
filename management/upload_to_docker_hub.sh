#!/bin/bash

# Load environment variables from .container-env file
if [[ -f .container-env ]]; then
  while IFS='=' read -r key value; do
    if [[ ! $key =~ ^\s*# && -n $key ]]; then
      export "$key"="${value//\"/}"
    fi
  done < .container-env
else
  echo ".container-env file not found!"
  exit 1
fi

# Docker Hub username from environment variables
DOCKER_HUB_USERNAME=${DOCKER_HUB_USERNAME}

# Docker image tag (username/image-name:tag)
DOCKER_IMAGE_TAG="${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}:latest"

# Change directory to flask-app
cd ..

# Login to Docker Hub
docker login -u $DOCKER_HUB_USERNAME

# Build the Docker image with the correct architecture (linux/amd64) from the flask-app folder
docker build --platform linux/amd64 -t $DOCKER_IMAGE_TAG .

# Push the Docker image to Docker Hub
docker push $DOCKER_IMAGE_TAG

# Go back to the previous directory
cd management

# Update the .env file with the new DOCKER_IMAGE_TAG
if [[ -f .env ]]; then
  # Create a temporary file without the DOCKER_IMAGE_TAG line
  awk '!/^DOCKER_IMAGE_TAG=/' .env > .env.tmp && mv .env.tmp .env
  # Append the new DOCKER_IMAGE_TAG
  echo "DOCKER_IMAGE_TAG=${DOCKER_IMAGE_TAG}" >> .env
else
  echo ".env file not found!"
  exit 1
fi

echo "Docker image built and pushed successfully: ${DOCKER_IMAGE_TAG}"