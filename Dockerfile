# syntax=docker/dockerfile:1.7
# AddACCION Auth - Native AOT image.
#   build:  docker build -t addaccion/auth:dev .
#   result: ~115 MB image (chiseled + ICU, no shell, no package manager), non-root, ~90 ms to first response.

ARG DOTNET_VERSION=10.0

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION}-noble AS build
ARG TARGETARCH
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# Restore first (cached layer).
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/AddAccion.Auth/AddAccion.Auth.csproj src/AddAccion.Auth/
RUN RID=$([ "$TARGETARCH" = "arm64" ] && echo linux-arm64 || echo linux-x64) \
 && dotnet restore src/AddAccion.Auth/AddAccion.Auth.csproj -r $RID

COPY db/ db/
COPY src/ src/
RUN RID=$([ "$TARGETARCH" = "arm64" ] && echo linux-arm64 || echo linux-x64) \
 && dotnet publish src/AddAccion.Auth/AddAccion.Auth.csproj -c Release -r $RID --no-restore -o /app \
 && rm -f /app/*.dbg

# Runtime: chiseled Ubuntu with ICU (required by Microsoft.Data.SqlClient). Runs as the non-root "app" user (UID 1654).
FROM mcr.microsoft.com/dotnet/runtime-deps:${DOTNET_VERSION}-noble-chiseled-extra AS runtime
WORKDIR /app
COPY --from=build --chown=root:root --chmod=0555 /app/ /app/
ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_gcServer=1 \
    DOTNET_GCDynamicAdaptationMode=1
EXPOSE 8080
USER app
ENTRYPOINT ["/app/AddAccion.Auth"]
