# WinSentinel Linux container images.
# The CLI and service remain Windows-security tools; Linux containers provide a
# reliable packaging/runtime surface for cross-platform-capable audits.

ARG DOTNET_SDK_TAG=8.0
ARG DOTNET_RUNTIME_TAG=8.0
ARG VERSION=0.0.0-dev
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_SDK_TAG} AS build
ARG VERSION
WORKDIR /src

COPY Directory.Build.props Directory.Packages.props WinSentinel.sln ./
COPY src/WinSentinel.Core/WinSentinel.Core.csproj src/WinSentinel.Core/
COPY src/WinSentinel.Cli/WinSentinel.Cli.csproj src/WinSentinel.Cli/
COPY src/WinSentinel.Service/WinSentinel.Service.csproj src/WinSentinel.Service/
RUN dotnet restore src/WinSentinel.Cli/WinSentinel.Cli.csproj -r linux-x64 \
 && dotnet restore src/WinSentinel.Service/WinSentinel.Service.csproj -r linux-x64 -p:TargetFramework=net8.0

COPY src/ src/
RUN dotnet publish src/WinSentinel.Cli/WinSentinel.Cli.csproj \
    -c Release -r linux-x64 --self-contained --no-restore \
    -o /app/cli \
    -p:PublishSingleFile=true \
    -p:IncludeNativeLibrariesForSelfExtract=true \
    -p:Version=${VERSION} \
 && dotnet publish src/WinSentinel.Service/WinSentinel.Service.csproj \
    -c Release -r linux-x64 --self-contained --no-restore \
    -o /app/service \
    -p:TargetFramework=net8.0 \
    -p:Version=${VERSION}

FROM mcr.microsoft.com/dotnet/runtime-deps:${DOTNET_RUNTIME_TAG}-bookworm-slim AS cli
ARG VERSION
ARG BUILD_DATE
ARG VCS_REF
LABEL org.opencontainers.image.title="WinSentinel CLI" \
      org.opencontainers.image.description="Security auditing from the command line" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/sauravbhattacharya001/WinSentinel" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=build /app/cli .
USER 65532:65532
HEALTHCHECK --interval=60s --timeout=10s --retries=3 CMD ["./winsentinel", "version"]
ENTRYPOINT ["./winsentinel"]
CMD ["audit", "--full"]

FROM mcr.microsoft.com/dotnet/runtime-deps:${DOTNET_RUNTIME_TAG}-bookworm-slim AS service
ARG VERSION
ARG BUILD_DATE
ARG VCS_REF
LABEL org.opencontainers.image.title="WinSentinel Service" \
      org.opencontainers.image.description="WinSentinel background monitoring service" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/sauravbhattacharya001/WinSentinel" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=build /app/service .
USER 65532:65532
ENTRYPOINT ["./WinSentinel.Service"]
