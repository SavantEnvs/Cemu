# syntax=docker/dockerfile:1.7
#
# Commit image for Cemu (Wii U emulator). Builds the libFuzzer harnesses in mayhem/harnesses/
# against Cemu's own parser sources (compiled with ASan+UBSan by mayhem/build.sh).
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile --build-arg COMMIT=$(git rev-parse HEAD) -t cemu .
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# Header/library deps Cemu's sources include (precompiled.h pulls boost, glm; WUHB/meta.xml use
# pugixml; FileCache/prudp/ncrypto use zlib/OpenSSL). Pinned via SOURCE_DATE_EPOCH when set.
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
        libboost-dev libglm-dev libpugixml-dev zlib1g-dev libssl-dev libx11-dev libxrender-dev \
 && rm -rf /var/lib/apt/lists/*

# Cemu requires fmt >= 12.1 (CMakeLists.txt: find_package(fmt 12.1 REQUIRED)); Debian ships 10.x.
# Built once from the pinned release tarball into a static, read-only prefix (SPEC §6.2 item 19).
ARG FMT_VER=12.1.0
ARG FMT_SHA256=ea7de4299689e12b6dddd392f9896f08fb0777ac7168897a244a6d6085043fea
RUN d=/opt/toolchains/deps/fmt-${FMT_VER} && mkdir -p "$d/src" /tmp/dep-build \
 && curl -fsSL -o /tmp/dep.tgz https://github.com/fmtlib/fmt/archive/refs/tags/${FMT_VER}.tar.gz \
 && echo "${FMT_SHA256}  /tmp/dep.tgz" | sha256sum -c - \
 && tar -xzf /tmp/dep.tgz --strip-components=1 -C "$d/src" \
 && cmake -S "$d/src" -B /tmp/dep-build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_FLAGS="-O2 -g -gdwarf-3" -DFMT_TEST=OFF -DFMT_DOC=OFF -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX="$d" -DCMAKE_INSTALL_LIBDIR=lib \
 && cmake --build /tmp/dep-build && cmake --install /tmp/dep-build \
 && rm -rf /tmp/dep-build /tmp/dep.tgz && chmod -R a+rX,a-w "$d"

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
