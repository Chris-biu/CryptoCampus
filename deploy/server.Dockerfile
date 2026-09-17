ARG OPENHITLS_REF=a6b28e09f186dd0402b1236d8b4455842694fce4

FROM ubuntu:24.04 AS crypto-builder

ARG OPENHITLS_REF

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN (git clone --filter=blob:none --no-checkout https://gitee.com/openHiTLS/openHiTLS.git openhitls \
        || git clone --filter=blob:none --no-checkout https://github.com/openHiTLS/openHiTLS.git openhitls) \
    && git -C openhitls fetch --depth 1 origin "$OPENHITLS_REF" \
    && git -C openhitls checkout --detach "$OPENHITLS_REF" \
    && test "$(git -C openhitls rev-parse HEAD)" = "$OPENHITLS_REF"
RUN cmake -S openhitls -B openhitls/build \
    && cmake --build openhitls/build --parallel 2

COPY bridge /src/bridge
RUN cmake -S bridge -B bridge/build \
        -DBUILD_TESTING=ON \
        -DOPENHITLS_ROOT=/src/openhitls \
    && cmake --build bridge/build --parallel 2 \
    && ctest --test-dir bridge/build --output-on-failure

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/opt/cryptocampus/server \
    CC_BRIDGE_LIBRARY=/opt/cryptocampus/lib/libcc_bridge.so \
    LD_LIBRARY_PATH=/opt/cryptocampus/lib

WORKDIR /opt/cryptocampus/server

RUN addgroup --system --gid 10001 cryptocampus \
    && adduser --system --uid 10001 --ingroup cryptocampus --home /nonexistent --no-create-home cryptocampus \
    && mkdir -p /var/lib/cryptocampus /opt/cryptocampus/lib \
    && chown -R cryptocampus:cryptocampus /var/lib/cryptocampus /opt/cryptocampus

COPY server/requirements.txt ./requirements.txt
RUN python -m pip install --disable-pip-version-check -r requirements.txt

COPY --from=crypto-builder /src/bridge/build/libcc_bridge.so /opt/cryptocampus/lib/
COPY --from=crypto-builder /src/openhitls/build/libhitls_bsl.so /opt/cryptocampus/lib/
COPY --from=crypto-builder /src/openhitls/build/libhitls_crypto.so /opt/cryptocampus/lib/
COPY --from=crypto-builder /src/openhitls/build/libhitls_pki.so /opt/cryptocampus/lib/
COPY --chown=cryptocampus:cryptocampus bridge/wrapper /opt/cryptocampus/bridge/wrapper
COPY --chown=cryptocampus:cryptocampus server/app ./app

USER cryptocampus
EXPOSE 8000

CMD ["sh", "-c", "python -m app.db.init_db && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
