# syntax=docker/dockerfile:1
#
# The issuer image. Build from the repository root:
#
#   docker build -f src/Proof.Issuer/Dockerfile --build-arg VERSION=1.2.3 .
#
# Runs as a non-root user on a chiseled (shell-less) ASP.NET image, listening for HTTP on 8080. Settings come from
# Proof__* environment variables; the allowlist and signing key are mounted at the paths set below. See README.md.

# The SDK stage runs on the build machine and cross-compiles, so a multi-platform build needs no emulation.
# The SDK global.json pins: its bundled packages (ILLink) are in the lock files.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0.302 AS build
ARG TARGETARCH
# The context has no .git, so the version comes in as arguments (build/Version.targets).
ARG VERSION=0.0.0-0.dev.0
ARG COMMIT=
WORKDIR /src

COPY global.json Directory.Build.props ./
COPY build/ build/
COPY src/Proof.Shared/Proof.Shared.csproj src/Proof.Shared/packages.lock.json src/Proof.Shared/
COPY src/Proof.Issuer/Proof.Issuer.csproj src/Proof.Issuer/packages.lock.json src/Proof.Issuer/
RUN dotnet restore src/Proof.Issuer/Proof.Issuer.csproj -a $TARGETARCH --locked-mode

COPY src/Proof.Shared/ src/Proof.Shared/
COPY src/Proof.Issuer/ src/Proof.Issuer/
RUN dotnet publish src/Proof.Issuer/Proof.Issuer.csproj -c Release -a $TARGETARCH --no-restore -o /app \
      -p:DebugType=none -p:ProofVersion=$VERSION -p:ProofCommit=$COMMIT

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled
ARG VERSION=0.0.0-0.dev.0
LABEL org.opencontainers.image.title="proof-issuer" \
      org.opencontainers.image.description="Proof issuer: trades Hyper-V host tokens for audience-specific JWTs" \
      org.opencontainers.image.source="https://github.com/charlespick/Proof" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="$VERSION"

WORKDIR /app
COPY --from=build /app ./
COPY LICENSE ./

# Mount the allowlist ConfigMap as a directory at /etc/proof/allowlist (not a subPath, so updates arrive) and the
# signing key Secret at /etc/proof/signing. Proof__IssuerUrl has no default and must be set.
ENV Proof__AllowlistPath=/etc/proof/allowlist/allowlist.yaml \
    Proof__SigningKeyPath=/etc/proof/signing/signing-key.pem \
    Logging__Console__FormatterName=json

EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["./proof-issuer"]
