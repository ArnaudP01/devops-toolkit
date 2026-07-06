# 🧰 devops-toolkit

> A growing collection of small, focused **bash & Python** scripts for everyday DevOps work.
> No bloat, no dependencies — just things you actually reach for.

[![CI](https://github.com/ArnaudP01/devops-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/ArnaudP01/devops-toolkit/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Each script is **self-contained**, documented at the top, and safe to read before running.
The bash scripts are Linux/macOS-oriented; the Python scripts run anywhere Python 3.9+ does.

---

## 📜 Bash scripts (`scripts/bash/`)

| Script | What it does | Example |
| --- | --- | --- |
| `sysinfo.sh` | One-shot system snapshot: host, uptime/load, memory, disk, top CPU procs, listening ports | `./sysinfo.sh` |
| `docker-cleanup.sh` | Reclaim disk by pruning unused images/containers/networks (dry-run supported) | `./docker-cleanup.sh --dry-run` |
| `ssl-cert-check.sh` | Show a TLS cert's expiry date and warn when it's near | `./ssl-cert-check.sh example.com 443 30` |
| `backup.sh` | Timestamped compressed backup of a dir, keeps the last N | `./backup.sh /var/www /backups 7` |
| `git-prune-branches.sh` | Delete local branches already merged into main/master | `./git-prune-branches.sh` |

```bash
git clone https://github.com/ArnaudP01/devops-toolkit.git
cd devops-toolkit
chmod +x scripts/bash/*.sh
./scripts/bash/sysinfo.sh
```

## 🐍 Python scripts (`scripts/python/`) — stdlib only

| Script | What it does | Example |
| --- | --- | --- |
| `password_gen.py` | Cryptographically strong password generator (`secrets`) | `python password_gen.py -l 24 -n 3` |
| `log_analyzer.py` | Summarize an access log: top client IPs + status codes | `python log_analyzer.py access.log --top 10` |
| `port_scanner.py` | Fast concurrent TCP port scanner | `python port_scanner.py example.com --start 1 --end 1024` |
| `env_compare.py` | Diff two `.env` files by key (missing / extra) | `python env_compare.py .env.prod .env.staging` |
| `disk_top.py` | Find the largest files in a directory tree | `python disk_top.py /var/log -n 20` |

```bash
python scripts/python/password_gen.py -l 24
python scripts/python/env_compare.py .env.example .env
```

Every Python script supports `--help`.

---

## ✅ Quality

- **Python scripts** are unit-tested (`pytest`) — parsing logic, sorting, and password rules.
- **Bash scripts** are syntax-checked (`bash -n`) on every push.
- Both run on **GitHub Actions** across Python 3.9 → 3.12.

```bash
make help           # list targets
make test           # run the Python tests
make check-scripts  # syntax-check every bash script
```

## 📁 Project structure

```
devops-toolkit/
├── scripts/
│   ├── bash/        # 5 ops scripts (Linux/macOS)
│   └── python/      # 5 stdlib-only utility scripts
├── tests/           # pytest — scripts imported as modules
├── .github/workflows/ci.yml
└── Makefile
```

## 🤝 Adding a script

1. Drop it in the right folder (`scripts/bash/` or `scripts/python/`).
2. Add a docstring / `# usage:` header comment.
3. (Python) add a test in `tests/test_scripts.py`.
4. (Bash) `make check-scripts` — it will be picked up automatically.

## 📝 License

[MIT](LICENSE)
