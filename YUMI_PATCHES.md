# Yumi-Lab patches on sonar

This repository is a fork of [mainsail-crew/sonar](https://github.com/mainsail-crew/sonar).
Every block that differs from upstream is marked `# YUMI:` in `sonar.py`, with what it
adds or changes. This file says why each one exists and how to sync with upstream.

## Sync with upstream

```bash
git remote add upstream https://github.com/mainsail-crew/sonar.git   # once
git fetch upstream
git merge upstream/main            # on a branch, then a pull request into main
python3 -m unittest discover -s tests
```

A conflict only happens where upstream touched a `# YUMI:` block: keep the Yumi logic on
top of the new upstream code. Last sync: upstream `74494cc` (2026-09-22, default routes
without `src`).

## What the fork changes, and why

All measured on Yumi printers with USB WiFi dongles (RTL8188EUS, `rtl8xxxu`).

| Option / behaviour | Why |
|---|---|
| `loss_threshold`, `loss_streak` | A link that keeps its association and IP but drops most frames passed the upstream check (one reply out of three was enough). |
| `dongle_recovery`, `dongle_recovery_threshold` | A wedged dongle stops scanning entirely; only a driver reload or a USB rebind brings it back. |
| `soft_recoveries_before_reload` | A half-wedged dongle associates but never gets a lease or never reaches the gateway; soft reconnects alone looped for 50 minutes. |
| per-device `nmcli` reconnect | Restarting NetworkManager tore every interface down, ethernet included. |
| live gateway (`live_target`) | After NetworkManager moved to another network, sonar kept pinging the old gateway and tore the working link down. |
| no saved WiFi profile = nothing to recover | An ethernet-only machine looped on NetworkManager restarts and wedged healthy dongles. |
| no forced driver reload when no saved network is in range | Carried away from its network, a machine scanned its neighbours fine and still got its driver reloaded 25 times in a row, every 1.5 min. |
| `deaf_timeout` (default 180 s) | The adapter stopped receiving broadcast frames while everything else worked: ARP requests never arrived and the host was unreachable from the network. On by default because an update never rewrites `sonar.conf`. |

The tests in `tests/` cover the Yumi behaviours and run without a network
(`subprocess` and time are mocked).
