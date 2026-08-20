#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found. Install Docker first: https://docs.docker.com/engine/install/"
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "Neither 'docker compose' nor 'docker-compose' found. Install the Compose plugin."
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "node not found. Install Node.js >= 20 first."
  exit 1
fi

NODE_MAJOR="$(node -e 'console.log(process.versions.node.split(".")[0])')"
if [ "$NODE_MAJOR" -lt 20 ]; then
  echo "Node.js >= 20 is required (found $(node -v))."
  exit 1
fi

if [ ! -f .env ]; then
  JWT_SECRET="$(openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | xxd -p | tr -d '\n')"
  cat > .env <<EOF
JWT_SECRET=${JWT_SECRET}
DOCSERVER_PORT=6969
EOF
  echo "Generated .env with a new JWT secret."
else
  echo ".env already exists, reusing it."
fi
source .env
DOCSERVER_PORT="${DOCSERVER_PORT:-6969}"

echo "Starting ONLYOFFICE Document Server..."
"${COMPOSE[@]}" up -d

echo -n "Waiting for it to become healthy"
for i in $(seq 1 60); do
  if curl -fs "http://localhost:${DOCSERVER_PORT}/healthcheck" 2>/dev/null | grep -qi true; then
    echo " — up."
    break
  fi
  echo -n "."
  sleep 3
  if [ "$i" -eq 60 ]; then
    echo
    echo "Document Server didn't report healthy after 3 minutes."
    echo "Check logs: ${COMPOSE[*]} logs -f documentserver"
    exit 1
  fi
done

LAN_IP="$(node -e "
const os = require('os');
const ifaces = os.networkInterfaces();
for (const name of Object.keys(ifaces)) {
  for (const i of ifaces[name]) {
    if (i.family === 'IPv4' && !i.internal) { console.log(i.address); process.exit(0); }
  }
}
console.log('127.0.0.1');
")"

node hexcollab.js config server "http://${LAN_IP}:${DOCSERVER_PORT}"
node hexcollab.js config jwtSecret "${JWT_SECRET}"
node hexcollab.js kill >/dev/null 2>&1 || true

echo "Building standalone binary..."
BUILD_DIR="$(mktemp -d)"
cp hexcollab.js sea-config.json "$BUILD_DIR/"
pushd "$BUILD_DIR" >/dev/null

node --experimental-sea-config sea-config.json

NODE_BIN="$(command -v node)"
cp "$NODE_BIN" hexcollab

if command -v codesign >/dev/null 2>&1; then
  codesign --remove-signature hexcollab || true
fi

if [ "$(uname)" = "Darwin" ]; then
  npx --yes postject hexcollab NODE_SEA_BLOB hexcollab.blob \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 \
    --macho-segment-name NODE_SEA
else
  npx --yes postject hexcollab NODE_SEA_BLOB hexcollab.blob \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
fi

if command -v codesign >/dev/null 2>&1; then
  codesign --sign - hexcollab || true
fi

chmod +x hexcollab
popd >/dev/null

DEST="/usr/local/bin/hexcollab"
if [ ! -w "$(dirname "$DEST")" ]; then
  DEST="$HOME/.local/bin/hexcollab"
  mkdir -p "$HOME/.local/bin"
fi
cp "$BUILD_DIR/hexcollab" "$DEST"
chmod +x "$DEST"
rm -rf "$BUILD_DIR"

echo
echo "== Done =="
echo "Installed to $DEST"
echo "Document Server:  http://${LAN_IP}:${DOCSERVER_PORT}"
echo
case ":$PATH:" in
  *":$(dirname "$DEST"):"*) ;;
  *) echo "Add $(dirname "$DEST") to your PATH if it isn't already." ;;
esac
echo
echo "Try it:"
echo "  hexcollab share somefile.docx"
echo "  hexcollab cloudflare setup yourdomain.com"
