# 🧰 devops-toolkit

> A growing collection of small, focused **bash & Python** scripts for everyday DevOps work.
> **Organized by use case, not by language** — open the folder that matches what you're trying to do.

[![CI](https://github.com/ArnaudP01/devops-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/ArnaudP01/devops-toolkit/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Each script is **self-contained**, documented at the top, and safe to read before running.
Bash scripts target Linux/macOS; the Python scripts run anywhere Python 3.9+ does (stdlib only).

---

## 📂 By use case

### 🔭 `observability/` — *something looks off on a machine; figure out the state, fast*
| Script | Language | What it does |
| --- | --- | --- |
| `sysinfo.sh` | bash | One-shot snapshot: host, uptime/load, memory, disk, top CPU procs, listening ports |
| `disk_top.py` | python | List the largest files in a directory tree |
| `log_analyzer.py` | python | Summarize an access log: top client IPs + HTTP status distribution |

### 🔐 `security/` — *audit and harden: secrets, certificates, exposed ports*
| Script | Language | What it does |
| --- | --- | --- |
| `password_gen.py` | python | Cryptographically strong password generator (`secrets`) |
| `ssl-cert-check.sh` | bash | Print a TLS cert's expiry date and warn when it is near |
| `port_scanner.py` | python | Fast concurrent TCP port scanner |

### 🐳 `containers/` — *day-2 Docker housekeeping*
| Script | Language | What it does |
| --- | --- | --- |
| `docker-cleanup.sh` | bash | Reclaim disk by pruning unused images/containers/networks (dry-run supported) |

### 💾 `backups/` — *protect and retain data*
| Script | Language | What it does |
| --- | --- | --- |
| `backup.sh` | bash | Timestamped compressed backup of a dir, keeps the last N |

### ⚙️ `config/` — *manage configuration across environments*
| Script | Language | What it does |
| --- | --- | --- |
| `env_compare.py` | python | Diff two `.env` files by key (missing / extra) |

### 🌿 `source-control/` — *keep local git repos tidy*
| Script | Language | What it does |
| --- | --- | --- |
| `git-prune-branches.sh` | bash | Delete local branches already merged into main/master |

---

## ▶️ Usage

```bash
git clone https://github.com/ArnaudP01/devops-toolkit.git
cd devops-toolkit
chmod +x **/*.sh          # one-off: make bash scripts executable

./observability/sysinfo.sh
python security/password_gen.py -l 24
python config/env_compare.py .env.example .env
```

Every Python script supports `--help`; every bash script documents its usage in its header comment.

## ✅ Quality

- **Python scripts** are unit-tested (`pytest`) — parsing, sorting and password rules.
- **Bash scripts** are syntax-checked (`bash -n`) on every push.
- Both run on **GitHub Actions** across Python 3.9 → 3.12.

```bash
make help           # list targets
make test           # run the Python tests
make check-scripts  # syntax-check every bash script
```

## 📁 Structure

```
devops-toolkit/
├── observability/     # system & log inspection
├── security/          # secrets, certs, ports
├── containers/        # docker maintenance
├── backups/           # data protection & retention
├── config/            # environment configuration
├── source-control/    # git repo hygiene
├── tests/             # pytest — scripts imported as modules
├── .github/workflows/ci.yml
└── Makefile
```

## 🤝 Adding a script

1. Drop it in the **folder that matches its use case** (create one if none fits).
2. Add a `# usage:` header (bash) or a docstring (python).
3. (Python) add a test in `tests/test_scripts.py`.
4. (Bash) `make check-scripts` — it picks up every `*.sh` automatically.

## 📝 License

[MIT](LICENSE)
