FROM rust:1.86-bullseye

ENV DEBIAN_FRONTEND=noninteractive
ARG APT_ALLOW_INSECURE=0
ARG APT_MINIMAL=0
ARG DOTNET_SKIP=0

RUN printf 'Acquire::Check-Valid-Until \"false\";\n' > /etc/apt/apt.conf.d/99no-check-valid-until

RUN if [ "$APT_MINIMAL" = "1" ]; then \
      echo "[docker] Skipping apt packages (APT_MINIMAL=1)"; \
    else \
      if [ "$APT_ALLOW_INSECURE" = "1" ]; then \
        APT_UPDATE_FLAGS="-o Acquire::Check-Valid-Until=false -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowDowngradeToInsecureRepositories=true"; \
        APT_INSTALL_FLAGS="--allow-unauthenticated"; \
      else \
        APT_UPDATE_FLAGS="-o Acquire::Check-Valid-Until=false"; \
        APT_INSTALL_FLAGS=""; \
      fi \
      && apt-get update $APT_UPDATE_FLAGS \
      && APT_CACHE_DIR="/tmp/apt-archives" \
      && mkdir -p "$APT_CACHE_DIR" \
      && apt-get install -y --no-install-recommends $APT_INSTALL_FLAGS \
        -o Dir::Cache::Archives="$APT_CACHE_DIR" \
        -o Dir::Cache::pkgcache="" \
        -o Dir::Cache::srcpkgcache="" \
        debian-archive-keyring \
      && apt-get update $APT_UPDATE_FLAGS \
      && APT_PACKAGES="build-essential python3 python3-pip python3-venv openjdk-17-jdk maven curl gnupg ca-certificates pkg-config libssl-dev lld golang ruby-full patchelf" \
      && apt-get install -y --no-install-recommends $APT_INSTALL_FLAGS \
        -o Dir::Cache::Archives="$APT_CACHE_DIR" \
        -o Dir::Cache::pkgcache="" \
        -o Dir::Cache::srcpkgcache="" \
        $APT_PACKAGES \
      && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*; \
    fi

RUN if [ "$DOTNET_SKIP" = "1" ]; then \
      echo "[docker] Skipping dotnet install (DOTNET_SKIP=1)"; \
    else \
      curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
      && chmod +x /tmp/dotnet-install.sh \
      && /tmp/dotnet-install.sh --install-dir /usr/share/dotnet --channel 8.0 --no-path \
      && ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet \
      && rm /tmp/dotnet-install.sh; \
    fi

# Install Node.js 20 LTS
RUN if [ "$APT_MINIMAL" = "1" ]; then \
      echo "[docker] Skipping Node.js install (APT_MINIMAL=1)"; \
    else \
      curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
      && apt-get install -y --no-install-recommends nodejs \
      && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*; \
    fi

ENV BUN_INSTALL=/root/.bun
RUN if [ "$APT_MINIMAL" = "1" ]; then \
      echo "[docker] Skipping bun install (APT_MINIMAL=1)"; \
    else \
      curl -fsSL https://bun.sh/install | bash \
      && ln -s /root/.bun/bin/bun /usr/local/bin/bun; \
    fi

# Python tooling
RUN if [ "$APT_MINIMAL" = "1" ]; then \
      echo "[docker] Skipping Python tooling install (APT_MINIMAL=1)"; \
    else \
      pip3 install --no-cache-dir maturin==1.9.4 pytest==8.4.1; \
    fi

RUN if [ "$APT_MINIMAL" = "1" ]; then \
      echo "[docker] Skipping rustup components (APT_MINIMAL=1)"; \
    else \
      rustup component add rustfmt clippy; \
    fi

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

WORKDIR /workspace

ENTRYPOINT ["/bin/bash"]
