FROM rust:1.86-bullseye

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    openjdk-17-jdk \
    maven \
    curl \
    gnupg \
    ca-certificates \
    pkg-config \
    libssl-dev \
    lld \
    golang \
    ruby-full \
    patchelf

RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --install-dir /usr/share/dotnet --channel 8.0 --no-path \
    && ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet \
    && rm /tmp/dotnet-install.sh

# Install Node.js 20 LTS
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Python tooling
RUN pip3 install --no-cache-dir maturin==1.9.4 pytest==8.4.1

RUN rustup component add rustfmt

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

WORKDIR /workspace

ENTRYPOINT ["/bin/bash"]
