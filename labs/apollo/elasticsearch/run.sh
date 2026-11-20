#!/usr/bin/env bash
# Start a fresh loopback-only node using an unpacked Elasticsearch distribution.
set -euo pipefail
umask 077
: "${ES_HOME:?Set ES_HOME to the extracted Elasticsearch installation}"
lab=$(mktemp -d)
pid=
cleanup() {
    if [[ -n "$pid" ]]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf -- "$lab"
}
trap cleanup EXIT
export ES_PATH_CONF="$lab/config"
cp -r "$ES_HOME/config" "$ES_PATH_CONF"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 -subj '/CN=BLUE2 loopback' \
    -addext 'subjectAltName=IP:127.0.0.1' -keyout "$ES_PATH_CONF/lab.key" \
    -out "$ES_PATH_CONF/lab.crt" 2>"$lab/cert.log"
cat >"$ES_PATH_CONF/elasticsearch.yml" <<YAML
cluster.name: olympus-blue2-lab
network.host: 127.0.0.1
http.port: 19200
transport.port: 19300
discovery.type: single-node
path.data: "$lab/data"
path.logs: "$lab/logs"
xpack.security.enabled: true
xpack.security.autoconfiguration.enabled: false
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.key: lab.key
xpack.security.http.ssl.certificate: lab.crt
xpack.ml.enabled: false
ingest.geoip.downloader.enabled: false
YAML
BLUE2_BOOTSTRAP_PASSWORD=$(openssl rand -hex 32)
export BLUE2_BOOTSTRAP_PASSWORD
if [[ ! -f "$ES_PATH_CONF/elasticsearch.keystore" ]]; then
    "$ES_HOME/bin/elasticsearch-keystore" create >/dev/null
fi
printf '%s\n' "$BLUE2_BOOTSTRAP_PASSWORD" | "$ES_HOME/bin/elasticsearch-keystore" add -xf bootstrap.password
ES_JAVA_OPTS="-Xms512m -Xmx512m ${ES_JAVA_OPTS:-}" "$ES_HOME/bin/elasticsearch" >"$lab/start.log" 2>&1 &
pid=$!
for ((attempt=0; attempt<90; attempt++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
        tail -30 "$lab/start.log" >&2
        exit 1
    fi
    # 401 proves that TLS is trusted and the node requires authentication.
    status=$(curl --noproxy '*' --max-time 2 --silent --output /dev/null --write-out '%{http_code}' \
        --cacert "$ES_PATH_CONF/lab.crt" https://127.0.0.1:19200/ || true)
    if [[ "$status" == 401 ]] && printf 'user = "elastic:%s"\n' "$BLUE2_BOOTSTRAP_PASSWORD" | \
        curl --config - --noproxy '*' --max-time 4 --silent --fail --output /dev/null \
            --cacert "$ES_PATH_CONF/lab.crt" 'https://127.0.0.1:19200/_cluster/health?wait_for_status=yellow&timeout=2s'; then
        python "$(dirname "$0")/verify.py" "$ES_PATH_CONF/lab.crt"
        exit 0
    fi
    sleep 2
done
echo 'Elasticsearch startup timed out' >&2
exit 1
