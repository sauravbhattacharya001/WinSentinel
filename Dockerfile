# WinSentinel Docker Image
# Builds the CLI tool for Windows Server Core containers.
# WinSentinel uses Windows-specific APIs (WMI, Registry, EventLog, Defender),
# so it requires Windows containers — Linux containers are not supported.
#
# Build:  docker build -t winsentinel .
# Run:    docker run --rm winsentinel audit --full
# Note:   Requires Docker Desktop with Windows containers enabled,
#         or a Windows Server host with Docker EE.

# --- Build Stage ---
FROM mcr.microsoft.com/dotnet/sdk:8.0-windowsservercore-ltsc2022 AS build
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

RUN dotnet restore src/WinSentinel.Cli/WinSentinel.Cli.csproj
RUN dotnet restore src/WinSentinel.Service/WinSentinel.Service.csproj

# Copy remaining source
COPY src/ src/
COPY tests/ tests/

# Build CLI (self-contained for portability)
RUN dotnet publish src/WinSentinel.Cli/WinSentinel.Cli.csproj \
    -c Release -r win-x64 --self-contained \
    -o /app/cli \
    -p:PublishSingleFile=true \
    -p:IncludeNativeLibrariesForSelfExtract=true

# Build Service
RUN dotnet publish src/WinSentinel.Service/WinSentinel.Service.csproj \
    -c Release -r win-x64 --self-contained \
    -o /app/service

# --- Runtime Stage (CLI) ---
FROM mcr.microsoft.com/windows/servercore:ltsc2022 AS cli
WORKDIR /app
COPY --from=build /app/cli .

# WinSentinel needs admin privileges for full audit capabilities
USER ContainerAdministrator

ENTRYPOINT ["winsentinel.exe"]
CMD ["audit", "--full"]

# --- Runtime Stage (Service) ---
FROM mcr.microsoft.com/dotnet/runtime:8.0-windowsservercore-ltsc2022 AS service
WORKDIR /app
COPY --from=build /app/service .

USER ContainerAdministrator

ENTRYPOINT ["WinSentinel.Service.exe"]
