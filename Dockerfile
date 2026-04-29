# WinSentinel Docker Image
# Builds the CLI tool and background Service for Windows Server Core containers.
# WinSentinel uses Windows-specific APIs (WMI, Registry, EventLog, Defender),
# so it requires Windows containers — Linux containers are not supported.
#
# Build:  docker build -t winsentinel .
# Run:    docker run --rm winsentinel audit --full
# Test:   docker build --target test -t winsentinel-test .
# Note:   Requires Docker Desktop with Windows containers enabled,
#         or a Windows Server host with Docker EE.

# --- Build Arguments ---
ARG DOTNET_SDK_TAG=8.0-windowsservercore-ltsc2022
ARG DOTNET_RUNTIME_TAG=8.0-windowsservercore-ltsc2022
ARG VERSION=0.0.0-dev
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown

# --- Build Stage ---
FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_SDK_TAG} AS build
ARG VERSION
WORKDIR /src

# Copy solution and project files first for layer caching
COPY WinSentinel.sln .
COPY src/WinSentinel.Core/WinSentinel.Core.csproj src/WinSentinel.Core/
COPY src/WinSentinel.Cli/WinSentinel.Cli.csproj src/WinSentinel.Cli/
COPY src/WinSentinel.Agent/WinSentinel.Agent.csproj src/WinSentinel.Agent/
COPY src/WinSentinel.Service/WinSentinel.Service.csproj src/WinSentinel.Service/
COPY src/WinSentinel.App/WinSentinel.App.csproj src/WinSentinel.App/
COPY src/WinSentinel.Installer/WinSentinel.Installer.csproj src/WinSentinel.Installer/
COPY tests/WinSentinel.Tests/WinSentinel.Tests.csproj tests/WinSentinel.Tests/

RUN dotnet restore WinSentinel.sln

# Copy remaining source
COPY src/ src/
COPY tests/ tests/

# Build CLI (self-contained for portability)
RUN dotnet publish src/WinSentinel.Cli/WinSentinel.Cli.csproj ^
    -c Release -r win-x64 --self-contained --no-restore ^
    -o /app/cli ^
    -p:PublishSingleFile=true ^
    -p:IncludeNativeLibrariesForSelfExtract=true ^
    -p:Version=%VERSION%

# Build Service
RUN dotnet publish src/WinSentinel.Service/WinSentinel.Service.csproj ^
    -c Release -r win-x64 --self-contained --no-restore ^
    -o /app/service ^
    -p:Version=%VERSION%

# --- Test Stage (opt-in via --target test) ---
FROM build AS test
RUN dotnet test tests/WinSentinel.Tests/WinSentinel.Tests.csproj ^
    -c Release --no-restore ^
    --logger "console;verbosity=minimal" ^
    --results-directory /test-results

# --- Runtime Stage (CLI) ---
FROM mcr.microsoft.com/windows/servercore:ltsc2022 AS cli
ARG VERSION
ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="WinSentinel CLI" \
      org.opencontainers.image.description="Windows security auditing from the command line" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/sauravbhattacharya001/WinSentinel" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="sauravbhattacharya001"

WORKDIR /app
COPY --from=build /app/cli .

# WinSentinel needs admin privileges for full audit capabilities
USER ContainerAdministrator

# Health check: verify the binary responds to --version
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD winsentinel.exe version || exit 1

ENTRYPOINT ["winsentinel.exe"]
CMD ["audit", "--full"]

# --- Runtime Stage (Service) ---
FROM mcr.microsoft.com/dotnet/runtime:${DOTNET_RUNTIME_TAG} AS service
ARG VERSION
ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="WinSentinel Service" \
      org.opencontainers.image.description="WinSentinel background monitoring service" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/sauravbhattacharya001/WinSentinel" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="sauravbhattacharya001"

WORKDIR /app
COPY --from=build /app/service .

USER ContainerAdministrator

# Health check: verify the service process is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD powershell -Command "if (Get-Process -Name WinSentinel.Service -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"

ENTRYPOINT ["WinSentinel.Service.exe"]
