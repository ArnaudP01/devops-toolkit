# 🧰 devops-toolkit

> A growing collection of small, focused **bash & Python** scripts for everyday DevOps work.
> **Organized by use case, not by language** — open the folder that matches what you're trying to do.

[![CI](https://github.com/ArnaudP01/devops-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/ArnaudP01/devops-toolkit/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Each script is **self-contained**, documented at the top, and safe to read before running.
Bash scripts target Linux/macOS; the Python scripts run anywhere Python 3.10+ does (stdlib only).

---

## 📂 By use case

### 🔭 `observability/` — *something looks off on a machine; figure out the state, fast*
| Script | Language | What it does |
| --- | --- | --- |
| `sysinfo.sh` | bash | One-shot snapshot: host, uptime/load, memory, disk, top CPU procs, listening ports |
| `disk_top.py` | python | List the largest files in a directory tree |
| `log_analyzer.py` | python | Summarize an access log: top client IPs + HTTP status distribution |
| `cron_audit.sh` | bash | Every scheduled job in one place: /etc/crontab, cron.d, user crontabs, periodic folders, systemd timers |

### 🔐 `security/` — *audit and harden: secrets, certificates, exposed ports*
| Script | Language | What it does |
| --- | --- | --- |
| `password_gen.py` | python | Cryptographically strong password generator (`secrets`) |
| `ssl-cert-check.sh` | bash | Print a TLS cert's expiry date and warn when it is near |
| `port_scanner.py` | python | Fast concurrent TCP port scanner |
| `cert_inventory.py` | python | TLS certificates of many hosts in one table, sorted by days left: name coverage (SAN), trusted chain, issuer. `--json` for monitoring |
| `php_malware_scan.py` | python | Triage a PHP site for injected code: eval-of-decoded data, request data executed, obfuscation, PHP hidden in uploads/ or images. Reports locations only, never the code |
| `file_integrity.py` | python | Fingerprint a tree (SHA-256), then report added / removed / modified files: watch a site after a clean-up or a release |
| `ssh_audit.sh` | bash | Effective sshd hardening (`sshd -T`), accounts with a login shell, their authorized keys (type + comment only), chroot rules |

### 🌐 `dns/` — *"mail goes to spam" / "the site works for me but not for them"*
| Script | Language | What it does |
| --- | --- | --- |
| `dns_audit.py` | python | Built-in DNS client (no `dig` needed). `ns`: ask every authoritative server directly: REFUSED, lame delegation, SOA serials out of sync. `mail`: MX, SPF (single record, `all` qualifier, 10-lookup limit), DMARC policy, DKIM selectors |
| `dns_compare.py` | python | Diff a zone between the old and the new name servers *before* changing the delegation |

### 🚚 `web/` — *moving a site without breaking it*
| Script | Language | What it does |
| --- | --- | --- |
| `migration_check.py` | python | Request the same URLs from the old and the new server (real Host + SNI, pinned IPs) *before* the DNS switch; compare status, redirects, title and size. `--sitemap` to cover the whole site |

### 🐳 `containers/` — *day-2 Docker housekeeping*
| Script | Language | What it does |
| --- | --- | --- |
| `docker-cleanup.sh` | bash | Reclaim disk by pruning unused images/containers/networks (dry-run supported) |

### 💾 `backups/` — *protect and retain data*
| Script | Language | What it does |
| --- | --- | --- |
| `backup.sh` | bash | Timestamped compressed backup of a dir, keeps the last N |
| `mysql-backup.sh` | bash | One consistent, gzip-verified dump per MySQL/MariaDB database, credentials from an option file, keeps the last N |

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
python dns/dns_audit.py ns example.com
python dns/dns_audit.py mail example.com --dkim-selector default
python security/php_malware_scan.py /var/www/site --min-severity high
python security/cert_inventory.py -f hosts.txt --warn 21
python dns/dns_compare.py example.com --old ns1.oldhost.net --new ns1.newhost.com
python web/migration_check.py www.example.com --old 203.0.113.10 --new 198.51.100.20 --sitemap
```

### A site migration, end to end

```bash
python dns/dns_compare.py example.com --old ns1.old.net --new ns1.new.com    # zone copied right?
python web/migration_check.py www.example.com --old OLD_IP --new NEW_IP --sitemap  # pages identical?
# ... switch DNS ...
python dns/dns_audit.py ns example.com                                        # every NS in sync?
python security/cert_inventory.py www.example.com example.com                 # new certificate OK?
python security/file_integrity.py init /var/www/site -o ~/site.manifest.json  # baseline for later
```

Every Python script supports `--help`; every bash script documents its usage in its header comment.

## ✅ Quality

- **Python scripts** are unit-tested (`pytest`) — parsing, sorting, password rules, DNS wire-format
  decoding against hand-built packets, SPF/DMARC/DKIM rules, malware-indicator detection,
  certificate name matching, migration diffing and file-integrity manifests.
- **Python code** is linted with **ruff**; **bash scripts** with **shellcheck** and `bash -n`.
- Everything runs on **GitHub Actions**: a lint job, then tests across Python 3.10 → 3.13.

```bash
make help           # list targets
make test           # run the Python tests
make lint           # ruff + shellcheck, as CI does
make check-scripts  # syntax-check every bash script
```

## 📁 Structure

```
devops-toolkit/
├── observability/     # system, log and scheduled-job inspection
├── security/          # secrets, certs, ports, SSH, malware triage, file integrity
├── dns/               # name-server and mail DNS audits, zone diff
├── web/               # site migration checks
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
