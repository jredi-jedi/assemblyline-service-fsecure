FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH fsecure.FSecure

# Switch to assemblyline user
USER assemblyline

# Copy FSecure service code
WORKDIR /opt/al_service
COPY . .