FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential clang cmake git curl ca-certificates python3 pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Rust nightly + cargo-fuzz
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain nightly --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cargo-fuzz

# Pinned sources (see fuzz/README.md for why these commits)
WORKDIR /src
RUN git clone --filter=blob:none https://github.com/Chia-Network/pos2-chip.git pos2 \
    && cd pos2 && git fetch --depth 1 origin cdabddfa5fd993d9f715635973dd758e7e2c7718 \
    && git checkout -f cdabddfa5fd993d9f715635973dd758e7e2c7718
RUN git clone --filter=blob:none https://github.com/Chia-Network/chiapos.git chiapos \
    && cd chiapos && git fetch --depth 1 origin 254dc99bfc2873ef8c592868e54ed4ece022f50c \
    && git checkout -f 254dc99bfc2873ef8c592868e54ed4ece022f50c
RUN git clone --filter=blob:none https://github.com/Chia-Network/clvm_rs.git clvm_rs \
    && cd clvm_rs && git fetch --depth 1 origin 59d7e870dd4b4224309d8d0e7e952f186eac7eab \
    && git checkout -f 59d7e870dd4b4224309d8d0e7e952f186eac7eab

COPY harnesses/ /fuzz/harnesses/
COPY seeds/ /fuzz/seeds/
COPY build.sh /fuzz/build.sh
COPY run.sh /fuzz/run.sh

RUN bash /fuzz/build.sh

ENTRYPOINT ["/fuzz/run.sh"]
