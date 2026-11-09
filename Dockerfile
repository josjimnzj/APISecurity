# syntax=docker/dockerfile:1.7
# =============================================================================
# AddACCION Auth — container image (Render, Kubernetes, Docker).
#
#   docker build -t addaccion-auth .                               # Native AOT (default)
#   docker build --build-arg PUBLISH_AOT=false -t addaccion-auth . # fallback: self-contained + ReadyToRun
#
# Listens on 0.0.0.0:$PORT (Render injects PORT, default 10000; 8080 when unset).
# Runtime image: Ubuntu chiseled + ICU (SqlClient needs it), no shell, no package
# manager, non-root user "app" (UID 1654), works with a read-only root filesystem.
# =============================================================================

ARG DOTNET_VERSION=10.0

# ---------- build ------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION}-noble AS build
ARG TARGETARCH
ARG PUBLISH_AOT=true
WORKDIR /src

# Native AOT links with clang; only needed for the AOT build.
RUN if [ "$PUBLISH_AOT" = "true" ]; then \
      apt-get update \
      && apt-get install -y --no-install-recommends clang zlib1g-dev \
      && rm -rf /var/lib/apt/lists/*; \
    fi

# Restore in its own layer (cached while only sources change).
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/AddAccion.Auth/AddAccion.Auth.csproj src/AddAccion.Auth/
RUN RID=$([ "$TARGETARCH" = "arm64" ] && echo linux-arm64 || echo linux-x64) \
 && R2R=$([ "$PUBLISH_AOT" = "true" ] && echo false || echo true) \
 && dotnet restore src/AddAccion.Auth/AddAccion.Auth.csproj -r "$RID" -p:PublishAot="$PUBLISH_AOT" -p:PublishReadyToRun="$R2R"

COPY db/ db/
COPY src/ src/
RUN RID=$([ "$TARGETARCH" = "arm64" ] && echo linux-arm64 || echo linux-x64) \
 && if [ "$PUBLISH_AOT" = "true" ]; then \
      dotnet publish src/AddAccion.Auth/AddAccion.Auth.csproj -c Release -r "$RID" --no-restore -o /app; \
    else \
      dotnet publish src/AddAccion.Auth/AddAccion.Auth.csproj -c Release -r "$RID" --no-restore -o /app \
        -p:PublishAot=false --self-contained true -p:PublishReadyToRun=true -p:TieredPGO=true; \
    fi \
 && rm -f /app/*.dbg /app/*.pdb

# ---------- runtime ----------------------------------------------------------
FROM mcr.microsoft.com/dotnet/runtime-deps:${DOTNET_VERSION}-noble-chiseled-extra AS runtime
LABEL org.opencontainers.image.title="addaccion-auth" \
      org.opencontainers.image.description="AddACCION OAuth 2.1 / OpenID Connect token service"
WORKDIR /app
COPY --from=build --chown=root:root --chmod=0555 /app/ /app/
ENV PORT=8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_gcServer=1 \
    DOTNET_GCDynamicAdaptationMode=1
EXPOSE 8080
USER app
ENTRYPOINT ["/app/AddAccion.Auth"]
