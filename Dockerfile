FROM apify/actor-node:20

WORKDIR /usr/src/app

COPY . ./
USER root
RUN if command -v apk >/dev/null 2>&1; then \
      apk add --no-cache git python3 py3-pip py3-yaml; \
    elif command -v apt-get >/dev/null 2>&1; then \
      apt-get update \
      && apt-get install -y --no-install-recommends git python3 python3-pip python3-venv \
      && rm -rf /var/lib/apt/lists/*; \
    else \
      echo "No supported package manager found for installing git and python3" >&2; \
      exit 1; \
    fi
RUN npm ci --omit=dev

CMD ["node", "src/main.js"]
