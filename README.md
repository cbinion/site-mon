# site-mon

A small monitor for the TLS certificates and HTTP availability of domains I own.
It checks each site on a schedule, keeps the history in SQLite, and posts to
Discord before a certificate expires or when a site goes down.

## The problem

I run a handful of personal domains, and certificate renewal was a manual job I
did whenever I happened to notice it was due. That works right up until the one
time I don't notice. I wanted something that would tell me ahead of time, and
tell me if a site stopped answering.

This is a monitor, not a renewer. Automating renewal is a separate ops task and
deliberately not part of this codebase.

## What it checks

For each target in the config file, one pass:

1. **Opens a TLS connection and reads the leaf certificate.** It records the
   subject, issuer, DNS subject alternative names, validity dates, and days
   remaining. The connection uses Python's default SSL context, so the chain and
   hostname are verified the same way a browser would.
2. **Makes an HTTPS request** and records the status code and response time,
   compared against an expected status (200 by default, but a redirect can be
   the expected answer).
3. **Records the result as a row**, so there is a history and not just the
   current state.

Each check ends in one of four outcomes:

| Outcome           | Meaning                                                    |
| ----------------- | ---------------------------------------------------------- |
| `ok`              | Certificate valid, status code as expected                 |
| `cert_invalid`    | Reached the host, but the certificate failed verification  |
| `unreachable`     | DNS, connection, TLS handshake, or timeout failure          |
| `status_mismatch` | Everything connected, but the status code was wrong        |

## Alerts

One channel: a Discord webhook. Two kinds of alert:

- **Certificate expiry.** Configurable day thresholds (default 14, 7, 1). Each
  threshold fires once per certificate. If the worker was down and several
  thresholds were crossed at once, it sends one message rather than three.
  A renewed certificate has a new expiry date, which resets the thresholds.
- **Outcome changes.** An alert fires when a site's outcome differs from the
  last one I was told about: going down, recovering, or changing from one kind
  of failure to another. A steady outage does not repeat every run. Recoveries
  post without a mention, since they are good news.

Alert state is only written after Discord accepts the message, so a failed
delivery is retried on the next run instead of being lost.

## Design decisions

- **Python, standard library first.** The TLS check is stdlib `ssl` and
  `socket`, and the certificate comes from `getpeercert()`. That dict already
  holds everything v1 records, so there's no x509 parsing dependency. The only
  runtime dependencies are `requests`, `fastapi`, and `uvicorn`.
- **Expected failures vs. bugs.** Network failures all surface as `OSError`, so
  one handler covers "the site is down." Certificate verification errors are
  caught ahead of that, because "the host answered but the cert is bad" is a
  finding, not an outage. Anything else is treated as a bug in this code and is
  allowed to crash the run instead of being logged as a site outage.
- **Pure decision logic.** Evaluating a check and deciding whether an alert is
  due are pure functions that take data and return data. Network and database
  work happen around them. That is where most of the tests point.
- **SQLite.** One file, no server, and the history can be read with `sqlite3`
  from a shell. WAL mode lets the status endpoint read while a check writes.
- **A one-shot command on a systemd timer**, instead of a long-running process
  with its own scheduler. The timer runs every six hours, catches up on boot if
  a run was missed, and adds a small random delay. A failed run shows up in
  `systemctl status` without any extra code.
- **One timestamp per run.** Every row from a pass shares the same
  `checked_at`. That lets the status endpoint show exactly the latest run, so a
  target removed from the config stops appearing instead of lingering.
- **Config in TOML, secrets in the environment.** `config.toml` is gitignored
  and `config.example.toml` is committed. The webhook URL can come from
  `SITE_MON_DISCORD_WEBHOOK` so it lives in a root-only file on the host, and it
  is scrubbed from any error message before printing.
- **Container build.** A multi-stage Dockerfile builds the virtualenv with `uv`
  and copies only the venv into a slim runtime image that runs as a non-root
  user.

## Running it

Requires Python 3.14 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
cp config.example.toml config.toml   # then edit targets and webhook

uv run site-mon check                # one pass over every target
uv run site-mon serve                # GET /status as JSON on 127.0.0.1:8000
```

Tests and lint:

```bash
uv run pytest
uv run ruff check
uv run ruff format --check
```

Server deployment with Docker and systemd is covered in
[`deploy/README.md`](deploy/README.md).

## What I'd change

- **Record certificate details when verification fails.** Right now a
  `cert_invalid` row has no certificate data, because the handshake is rejected
  before the certificate can be read. For an expired cert, the expiry date is
  exactly the thing I'd want to see.
- **Check HTTP even when the cert is bad.** The HTTP request only runs after the
  certificate check succeeds, so a certificate problem hides whether the site
  itself is still serving.
- **Validate the config properly.** Hostnames are checked, but a missing key or
  wrong type still surfaces as a Python traceback rather than a clear message.
- **A health endpoint.** The deployment runs checks as a one-shot job with
  nothing listening, so there is currently no health endpoint for a platform to
  poll.
