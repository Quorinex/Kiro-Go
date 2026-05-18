# Kiro-Go on serv00

This package includes a ready-to-use `start.sh` for serv00.

## Package contents

- `kiro-go`: FreeBSD amd64 binary
- `web/`: admin panel static assets
- `start.sh`: restart-safe startup script for serv00
- `SERV00_DEPLOY.md`: this guide

## Directory layout

After extracting the archive on serv00, keep the files together in one app directory, for example:

```text
~/domains/kiro-go/
├── kiro-go
├── start.sh
├── SERV00_DEPLOY.md
├── web/
├── data/
├── run/
└── logs/
```

## 1. Upload and extract

Upload `kiro-go-freebsd-amd64.tar.gz` to serv00, then extract it:

```sh
mkdir -p ~/domains/kiro-go
cd ~/domains/kiro-go
tar -xzf ~/kiro-go-freebsd-amd64.tar.gz --strip-components=1
chmod +x kiro-go start.sh
```

If you prefer a different location, update your reverse proxy target to match the port configured below.

## 2. Create the config file

Kiro-Go reads its config from `data/config.json`. Create that file before first start:

```json
{
  "password": "replace-with-your-admin-password",
  "host": "127.0.0.1",
  "port": 18080,
  "accounts": []
}
```

Notes:

- Keep `host` as `127.0.0.1` on serv00.
- Replace `18080` with the local port you want to use.
- The admin password should stay in `data/config.json`; `start.sh` does not override it.

## 3. Start or restart the service

From the app directory:

```sh
cd ~/domains/kiro-go
./start.sh
```

What `start.sh` does:

- stops the old process if `run/kiro-go.pid` exists
- removes a stale pid file
- starts the new process with `CONFIG_PATH=data/config.json`
- writes logs to `logs/stdout.log`

## 4. Check logs

```sh
tail -f ~/domains/kiro-go/logs/stdout.log
```

If startup succeeds, Kiro-Go will listen on the host and port defined in `data/config.json`.

## 5. Reverse proxy on serv00

Create a serv00 domain or subdomain and reverse proxy it to:

```text
127.0.0.1:18080
```

Use the same port that you put in `data/config.json`.

After the proxy is active, open:

```text
https://your-domain/admin
```

## Common issues

### `/bin/sh^M: bad interpreter`

Your script was uploaded with Windows line endings. Convert it on serv00:

```sh
sed -i 's/\r$//' ~/domains/kiro-go/start.sh
chmod +x ~/domains/kiro-go/start.sh
```

### Admin page does not load

Make sure `web/` exists next to `kiro-go`. The binary serves `web/index.html` from the local filesystem.

### Config changes do not apply

Run `./start.sh` again. The script stops the old process first, then starts the new one.
