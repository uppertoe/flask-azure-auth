#!/bin/bash

# Load environment variables from .env file
set -o allexport
source ../.env
set -o allexport

# Docker Hub username from environment variables
DOCKER_HUB_USERNAME=${DOCKER_HUB_USERNAME}

# Docker image tag (username/image-name:tag)
DOCKER_IMAGE_TAG="${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}:latest"

# Change directory to flask-app
cd flask-app

# Login to Docker Hub
docker login -u $DOCKER_HUB_USERNAME

# Build the Docker image from the flask-app folder
docker build -t $DOCKER_IMAGE_TAG .

# Push the Docker image to Docker Hub
docker push $DOCKER_IMAGE_TAG

# Go back to the previous directory
cd ..

# Remove the existing DOCKER_IMAGE_TAG line if it exists
sed -i '/^DOCKER_IMAGE_TAG=/d' .env

# Append the new DOCKER_IMAGE_TAG line to the .env file
echo "DOCKER_IMAGE_TAG=${DOCKER_IMAGE_TAG}" >> .env

echo "Docker image built and pushed successfully: ${DOCKER_IMAGE_TAG}"
