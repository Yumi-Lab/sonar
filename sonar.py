#!/usr/bin/env python3
"""
Sonar - A WiFi Keepalive Daemon in Python

This program pings a target (e.g., the router) at regular intervals to detect a
WiFi outage. If an outage is detected, it attempts to restore the WiFi
connection by using various methods, such as wpa_cli reassociation, restarting
the dhcpcd service, or restarting the NetworkManager service.

Configuration:
  The program loads optional parameters from a configuration file (default:
  sonar.conf) in INI format. For example:

    [sonar]
    enable: true
    debug_log: false
    persistent_log: false
    target: auto
    count: 3
    interval: 60
    restart_threshold: 10
    loss_threshold: 100
    loss_streak: 1
    deaf_timeout: 180

  If "auto" is set for the target, the default gateway (router IP) is determined
  automatically.

  A check pings the target `count` times and reads the packet loss. The link is
  considered lost when the loss reaches `loss_threshold` percent (100 = only when
  no reply at all comes back, the historical behaviour) for `loss_streak`
  consecutive checks. A WiFi link that keeps its association and its IP but
  drops most frames (beacon loss on a marginal radio link) is only caught with a
  threshold below 100.

  `deaf_timeout` (seconds, 0 = off) catches a WiFi adapter that keeps its
  association, its IP and its outgoing traffic but stops RECEIVING broadcast and
  multicast frames: other hosts can no longer resolve its address (ARP) and the
  host is unreachable from the network, while every check made from the host
  itself still passes. Once the adapter has heard the network, `deaf_timeout`
  seconds without a single inbound broadcast/multicast frame trigger a WiFi
  reconnect. On by default: sonar.conf is written once at install and never
  rewritten by an update, so a default is the only way an existing machine
  gets it. 0 turns it off.

Note: If persistent_log is enabled, logs will be written to /var/log/sonar.log.
"""

import subprocess
import time
import configparser
import os
import re
import sys
import shutil
import logging
import socket
import struct
import ctypes
import threading

# YUMI: added (deaf_timeout), see YUMI_PATCHES.md
# Classic BPF run by the kernel on every frame of the WiFi interface: keep only
# INBOUND frames sent to a group address (broadcast or multicast: lowest bit of
# the first destination byte), so the listener thread wakes up for those alone
# and never for the host's own traffic or its unicast streams.
ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
PACKET_OUTGOING = 4
GROUP_RX_FILTER = [
    (0x20, 0, 0, 0xfffff004),         # ld  packet type (SKF_AD_PKTTYPE)
    (0x15, 3, 0, PACKET_OUTGOING),    # jeq outgoing -> drop
    (0x30, 0, 0, 0x00000000),         # ldb first destination byte
    (0x45, 0, 1, 0x00000001),         # jset group bit -> keep / drop
    (0x06, 0, 0, 0x00000040),         # ret keep (64 bytes are plenty)
    (0x06, 0, 0, 0x00000000),         # ret drop
]


class SonarDaemon:
    """Sonar - A WiFi Keepalive Daemon"""

    # YUMI: modified: logs the Yumi options; state for check_deafness, see YUMI_PATCHES.md
    def __init__(self, config_path=None):
        self.config = {}
        # Set up logging
        self.logger = logging.getLogger("sonar")
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('[%(asctime)s] %(message)s',
                                      datefmt='%m/%d/%Y %H:%M:%S')

        # Clear existing handlers
        self.logger.handlers = []

        # Set up console logging
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        # Load configuration
        self.load_config(config_path)
        # Inbound broadcast/multicast tracking (listen_group_frames)
        self.last_group_rx = time.monotonic()
        self.heard_group = False

        # Set up persistant logging if enabled
        if self.config['persistent_log']:
            log_file = "/var/log/sonar.log"
            try:
                formatter = logging.Formatter('[%(asctime)s] %(message)s',
                                              datefmt='%m/%d/%Y %H:%M:%S')
                fh = logging.FileHandler(log_file)
                fh.setFormatter(formatter)
                self.logger.addHandler(fh)
            except PermissionError:
                self.logger.warning(f"No permission to write to {log_file}. "
                                    f"Using stdout instead.")

        self.logger.info("Starting Sonar – WiFi Keepalive Daemon.")

        self.logger.info(f"Configuration loaded:")
        self.logger.info(f"  enable: {self.config['enable']}")
        self.logger.info(f"  debug_log: {self.config['debug_log']}")
        self.logger.info(f"  persistent_log: {self.config['persistent_log']}")
        self.logger.info(f"  target: {self.config['target']}")
        self.logger.info(f"  count: {self.config['count']}")
        self.logger.info(f"  interval: {self.config['interval']}")
        self.logger.info(f"  restart_threshold: {self.config['restart_threshold']}")
        self.logger.info(f"  loss_threshold: {self.config['loss_threshold']}%")
        self.logger.info(f"  loss_streak: {self.config['loss_streak']}")
        self.logger.info(f"  dongle_recovery: {self.config['dongle_recovery']}")
        self.logger.info(f"  dongle_recovery_threshold: {self.config['dongle_recovery_threshold']}")
        self.logger.info(f"  soft_recoveries_before_reload: {self.config['soft_recoveries_before_reload']}")
        self.logger.info(f"  deaf_timeout: {self.config['deaf_timeout']}")

        # Set debug level if needed
        if self.config['debug_log']:
            self.logger.setLevel(logging.DEBUG)
            self.logger.debug("Debug logging enabled.")

    # YUMI: modified: loss_threshold, loss_streak, dongle_recovery*, soft_recoveries_before_reload, deaf_timeout, see YUMI_PATCHES.md
    def load_config(self, config_path=None):
        cp = configparser.ConfigParser(inline_comment_prefixes='#')

        if config_path and os.path.exists(config_path):
            try :
                cp.read(config_path)
            except Exception as e:
                self.logger.warning(f"Error reading configuration file: {e}")
        else:
            self.logger.warning("No configuration file found. Using default values.")

        cp['DEFAULT'] = {
            'enable': 'false',
            'debug_log': 'false',
            'persistent_log': 'false',
            'target': 'auto',
            'count': '3',
            'interval': '60',
            'restart_threshold': '10',
            'loss_threshold': '100',
            'loss_streak': '1',
            'dongle_recovery': 'true',
            'dongle_recovery_threshold': '3',
            'soft_recoveries_before_reload': '3',
            'deaf_timeout': '180'
        }

        if not cp.has_section('sonar'):
            cp.add_section('sonar')

        self.config = {
            'enable': cp.getboolean('sonar', 'enable'),
            'debug_log': cp.getboolean('sonar', 'debug_log'),
            'persistent_log': cp.getboolean('sonar', 'persistent_log'),
            'target': cp.get('sonar', 'target'),
            'count': cp.getint('sonar', 'count'),
            'interval': cp.getint('sonar', 'interval'),
            'restart_threshold': cp.getint('sonar', 'restart_threshold'),
            'loss_threshold': cp.getint('sonar', 'loss_threshold'),
            'loss_streak': max(1, cp.getint('sonar', 'loss_streak')),
            'dongle_recovery': cp.getboolean('sonar', 'dongle_recovery'),
            'dongle_recovery_threshold':
                cp.getint('sonar', 'dongle_recovery_threshold'),
            'soft_recoveries_before_reload':
                max(1, cp.getint('sonar', 'soft_recoveries_before_reload')),
            'deaf_timeout': max(0, cp.getint('sonar', 'deaf_timeout'))
        }

    def _is_service_active(self, service_name):
        try:
            result = subprocess.run(["systemctl", "is-active", service_name],
                                    capture_output=True, text=True)
            return result.stdout.strip() == "active"
        except Exception:
            return False

    def get_default_gateway(self):
        # Regex pattern to extract gateway, device name, source IP, and metric
        pattern = r'default via (\S+)\s+dev (\S+)(?:.*?\bsrc (\S+))?(?:.*?\bmetric (\d+))?'

        try:
            route_output = subprocess.run(["ip", "route", "show", "default"],
                                          capture_output=True, text=True)

            if route_output.returncode != 0:
                self.logger.warning(f"Error retrieving default route: {route_output.stderr}")
                return None

            if route_output.stdout == "":
                self.logger.warning("No default route found.")
                return None

            matches = re.findall(pattern, route_output.stdout)

            if not matches:
                self.logger.warning("No matching routes found.")
                return None

            # Sort matches by metric (ascending; missing metric -> 0)
            matches.sort(key=lambda x: int(x[3]) if x[3] else 0)

            return {
                'gateway': matches[0][0],  # Gateway IP
                'interface': matches[0][1],  # Device name (e.g., wlan0)
                'src': matches[0][2] or None,  # Source IP (absent on static routes)
                'metric': int(matches[0][3]) if matches[0][3] else 0  # Metric (may be absent)
            }
        except Exception as e:
            self.logger.error(f"Error retrieving default gateway: {e}")
            return None

    # YUMI: added, see YUMI_PATCHES.md
    def get_wifi_interface(self):
        """Detect the first wireless network interface.

        Generic and hardware agnostic: a net device is wireless if it exposes
        a 'wireless' or 'phy80211' entry under /sys/class/net/<iface>/. Works
        for built-in adapters (wlan0) as well as USB dongles (wlxMAC) without
        any hardcoded name.
        """
        net_path = "/sys/class/net"
        try:
            for iface in sorted(os.listdir(net_path)):
                dev = os.path.join(net_path, iface)
                if os.path.exists(os.path.join(dev, "wireless")) or \
                        os.path.exists(os.path.join(dev, "phy80211")):
                    return iface
        except OSError as e:
            self.logger.error(f"Error scanning for WiFi interface: {e}")
        return None

    # YUMI: added, see YUMI_PATCHES.md
    def reload_wifi_driver(self, interface):
        """Last-resort recovery for a wedged WiFi adapter.

        When a (usually USB) dongle locks up it stops scanning entirely and no
        amount of 'nmcli' restarting brings it back — only re-initialising the
        hardware does. This derives the driver from sysfs and:
          1. rebinds the USB device (surgical, leaves other adapters alone), or
          2. falls back to reloading the kernel module.
        """
        if not interface:
            self.logger.warning("No WiFi interface found to reload.")
            return

        device = f"/sys/class/net/{interface}/device"

        # Capture the module name FIRST: once the device is unbound,
        # /sys/class/net/<iface> is gone and the name can no longer be
        # derived — a failed rebind would then leave the adapter dead with
        # no fallback (seen in the field: 13h without WiFi until reboot).
        module = ""
        try:
            module = os.path.basename(
                os.path.realpath(os.path.join(device, "driver", "module")))
            if module == "module":
                module = ""
        except OSError:
            pass

        # 1) USB unbind/bind — most reliable for USB dongles, and it does not
        #    touch a built-in adapter that might share the same module.
        try:
            driver = os.path.join(device, "driver")
            if os.path.exists(driver):
                drv_path = os.path.realpath(driver)
                if "usb" in drv_path:
                    usb_id = os.path.basename(os.path.realpath(device))
                    self.logger.info(f"Rebinding USB WiFi {interface} "
                                     f"({usb_id}) ...")
                    with open(os.path.join(drv_path, "unbind"), "w") as fh:
                        fh.write(usb_id)
                    time.sleep(2)
                    # The bind (driver probe) can fail transiently on a
                    # half-wedged dongle — retry before giving up on it.
                    for attempt in range(3):
                        try:
                            with open(os.path.join(drv_path, "bind"),
                                      "w") as fh:
                                fh.write(usb_id)
                            self.logger.info("USB rebind done.")
                            return
                        except (OSError, IOError) as e:
                            self.logger.warning(
                                f"USB bind attempt {attempt + 1}/3 "
                                f"failed: {e}")
                            time.sleep(3)
        except (OSError, IOError) as e:
            self.logger.warning(f"USB rebind failed ({e}), "
                                f"falling back to modprobe.")

        # 2) Reload the kernel module (covers non-USB / SDIO adapters too,
        #    and rescues a USB rebind whose driver probe kept failing).
        try:
            if module:
                self.logger.info(f"Reloading driver module '{module}' "
                                 f"for {interface} ...")
                subprocess.run(["modprobe", "-r", module], check=False)
                time.sleep(2)
                subprocess.run(["modprobe", module], check=False)
                self.logger.info("Driver module reloaded.")
            else:
                self.logger.warning(f"Could not determine driver module "
                                    f"for {interface}.")
        except OSError as e:
            self.logger.error(f"Driver reload failed: {e}")

    # YUMI: modified: per-device nmcli reconnect before a NetworkManager restart, see YUMI_PATCHES.md
    def restart_wifi(self, interface="wlan0"):
        exists_wpa_cli = shutil.which("wpa_cli")
        is_dhcpcd_active = self._is_service_active("dhcpcd")
        is_network_manager_active = self._is_service_active("NetworkManager")

        self.logger.info("Attempting to restart WiFi connection...")
        if exists_wpa_cli and is_dhcpcd_active:
            try:
                subprocess.run(["wpa_cli", "-i", interface, "reassociate"],
                               check=True)
                self.logger.info("WiFi reconnected using wpa_cli reassociate.")
                subprocess.run(["systemctl", "restart", "dhcpcd.service"],
                               check=True)
                self.logger.info("dhcpcd service restarted.")
            except subprocess.CalledProcessError:
                self.logger.warning("wpa_cli reassociate failed or failed to"
                                    " restart dhcpcd.")
        elif is_network_manager_active:
            # Per-device cycle first: restarting the whole NetworkManager
            # service tears down EVERY interface (ethernet included) and
            # races with KlipperScreen's NM monitoring — only fall back to
            # it when the targeted reconnect doesn't work.
            try:
                subprocess.run(["nmcli", "device", "disconnect", interface],
                               check=False, capture_output=True)
                time.sleep(2)
                subprocess.run(["nmcli", "device", "connect", interface],
                               check=True, capture_output=True)
                self.logger.info(f"WiFi {interface} reconnected via nmcli.")
            except subprocess.CalledProcessError:
                self.logger.warning(f"nmcli reconnect of {interface} failed,"
                                    f" restarting NetworkManager.")
                try:
                    subprocess.run(["systemctl", "restart",
                                    "NetworkManager.service"], check=True)
                    self.logger.info("NetworkManager service restarted.")
                except subprocess.CalledProcessError:
                    self.logger.warning("Restarting NetworkManager failed.")
        else:
            self.logger.error("No active service found to restart WiFi"
                              " connection.")

    # YUMI: added, see YUMI_PATCHES.md
    def wifi_scan_count(self, interface):
        """Number of APs the adapter can see right now (forced rescan).

        This is the reliable wedge detector for USB dongles (rtl8xxxu): a
        wedged adapter is still enumerated and its radio still reads
        'enabled', but it scans NOTHING. So '0 APs while other devices see
        plenty' == firmware crash. Crucially this also distinguishes a dead
        adapter (0 APs) from 'my AP is simply out of range' (still sees the
        neighbours' APs) — so we never reload the driver just because the
        target AP is off.

        Returns the AP count, or -1 if the probe itself failed (unknown —
        do NOT treat as wedged).
        """
        try:
            r = subprocess.run(
                ["nmcli", "-t", "-f", "BSSID", "device", "wifi", "list",
                 "ifname", interface, "--rescan", "yes"],
                capture_output=True, text=True, timeout=25)
            if r.returncode != 0:
                # nmcli refused (NetworkManager still starting, device not
                # ready...): empty output here means "no answer", not "0 APs".
                self.logger.debug(f"wifi_scan_count: nmcli exit {r.returncode}")
                return -1
            return len([ln for ln in r.stdout.splitlines() if ln.strip()])
        except (subprocess.SubprocessError, OSError) as e:
            self.logger.debug(f"wifi_scan_count probe failed: {e}")
            return -1

    # YUMI: added, see YUMI_PATCHES.md
    def saved_network_visible(self, interface):
        """Whether one of NetworkManager's saved WiFi networks is in the last
        scan of `interface`: True or False, None when it cannot be told.

        "Associates but never gets a lease" was also read when the saved network
        was simply out of range: the C335 was carried away from its MIFI on
        2026-11-09 and sonar reloaded the RTL8188EUS driver 25 times in a row,
        every 1.5 min, while the adapter scanned the 5 neighbouring networks
        perfectly well."""
        def unescape(value):
            return value.replace('\\:', ':').strip()
        try:
            names = subprocess.run(
                ["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"],
                capture_output=True, text=True, timeout=10)
            saved = set()
            for line in names.stdout.splitlines():
                name, _, ctype = line.rpartition(':')
                if ctype != "802-11-wireless":
                    continue
                ssid = subprocess.run(
                    ["nmcli", "-g", "802-11-wireless.ssid", "connection",
                     "show", unescape(name)],
                    capture_output=True, text=True, timeout=10)
                if ssid.stdout.strip():
                    saved.add(unescape(ssid.stdout))
            scan = subprocess.run(
                ["nmcli", "-t", "-f", "SSID", "device", "wifi", "list",
                 "ifname", interface, "--rescan", "no"],
                capture_output=True, text=True, timeout=10)
            if not saved or scan.returncode != 0:
                return None
            visible = {unescape(l) for l in scan.stdout.splitlines() if l.strip()}
            return bool(saved & visible)
        except (subprocess.SubprocessError, OSError) as e:
            self.logger.debug(f"saved_network_visible probe failed: {e}")
            return None

    # YUMI: added, see YUMI_PATCHES.md
    def recover_wifi(self, interface, force_reload=False):
        """Escalating recovery for one interface, wedge-aware.

        1. soft reconnect (nmcli per-device, NM restart fallback)
        2. if the adapter then still sees ZERO APs -> it's wedged, reload the
           driver / rebind USB (reload_wifi_driver). This is the path that
           the old 'N consecutive no-gateway cycles' trigger never reached
           when a phantom gateway (flapping link, or a parasitic eth0) kept
           resetting the counter — the wedge is detected directly instead.
        3. force_reload: reload even though the adapter scans. A half-wedged
           dongle still receives (it lists the APs, associates, NetworkManager
           says "connected") but transmits nothing: no DHCP lease, no gateway,
           and soft reconnects loop forever (bench, 2026-09-06: three drops in
           an afternoon, each fixed only by replugging the dongle). The main
           loop asks for it after soft_recoveries_before_reload failures.
        """
        self.restart_wifi(interface)
        time.sleep(5)
        if not self.config['dongle_recovery']:
            return False
        n = self.wifi_scan_count(interface)
        if n != 0 and force_reload and \
                self.saved_network_visible(interface) is False:
            # The adapter scans, but none of the networks it knows is around:
            # nothing is wedged, a reload would only wear the dongle out.
            self.logger.warning(
                f"{interface} sees {n} APs but none of the saved networks:"
                f" out of range, not a wedge. No driver reload.")
            return False
        if n == 0 or force_reload:
            self.logger.warning(
                f"{interface} sees {n} APs after restart — "
                + ("adapter wedged, reloading driver."
                   if n == 0 else
                   "associates but never gets a lease: reloading driver anyway."))
            self.reload_wifi_driver(interface)
            time.sleep(5)
            return True
        self.logger.debug(f"{interface} sees {n} APs — adapter scans fine,"
                          f" not a wedge (target AP may just be absent).")
        return False

    # YUMI: added, see YUMI_PATCHES.md
    def handle_no_gateway(self):
        """One cycle without a default route (WiFi fully down, or associated
        without a lease). Plain keepalive can do nothing here, so every
        dongle_recovery_threshold cycles recover the detected WiFi interface:
        a soft nmcli reconnect, plus a hardware driver reload when the adapter
        is wedged (0 APs) — or, after soft_recoveries_before_reload soft
        reconnects in a row that brought no gateway back, a reload anyway
        (half-wedged dongle: associates, "connected", never any lease).

        FIXED low threshold — do NOT back off exponentially here. An earlier
        exponential backoff pushed the retry interval up to ~96 cycles (20-40
        min): when the AP came back after an absence, sonar sat idle for up
        to half an hour before retrying, so in practice the link "never"
        reconnected and users rebooted. recover_wifi is cheap when the adapter
        scans fine (it won't reload a healthy dongle before the escalation),
        so retry it on a short, constant cadence.
        Returns True when a hardware reload was done this cycle."""
        self.no_gateway_cycles += 1
        self.logger.warning(f"No default gateway found "
                            f"(cycle {self.no_gateway_cycles}). Retrying...")
        reloaded = False
        if self.config['dongle_recovery'] and \
                self.no_gateway_cycles >= self.config['dongle_recovery_threshold']:
            wifi_if = self.get_wifi_interface()
            if wifi_if and not self.has_saved_wifi_profile():
                self.logger.info(
                    "No saved WiFi profile — nothing to reconnect "
                    "to, skipping recovery.")
            elif wifi_if:
                self.soft_recoveries += 1
                force = self.soft_recoveries >= \
                    self.config['soft_recoveries_before_reload']
                self.logger.info(
                    f"WiFi down for {self.no_gateway_cycles} cycles – "
                    f"recovering {wifi_if} (soft attempt "
                    f"{self.soft_recoveries}"
                    + (", escalating to a driver reload)" if force else ")"))
                reloaded = self.recover_wifi(wifi_if, force_reload=force)
                if reloaded:
                    self.soft_recoveries = 0
            self.no_gateway_cycles = 0
        return reloaded

    # YUMI: added (deaf_timeout), see YUMI_PATCHES.md
    def listen_group_frames(self):
        """Background thread: stamp every inbound broadcast/multicast frame on
        the WiFi interface (the kernel filter GROUP_RX_FILTER drops all else).
        Rebinds after any socket error: the interface can vanish and come back
        when the driver is reloaded."""
        while True:
            interface = self.get_wifi_interface()
            if interface is None:
                time.sleep(self.config['interval'])
                continue
            try:
                program = ctypes.create_string_buffer(b''.join(
                    struct.pack('HBBI', *ins) for ins in GROUP_RX_FILTER))
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.htons(ETH_P_ALL))
                sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER,
                                struct.pack('HL', len(GROUP_RX_FILTER),
                                            ctypes.addressof(program)))
                sock.bind((interface, 0))
                while True:
                    sock.recv(64)
                    self.last_group_rx = time.monotonic()
                    self.heard_group = True
            except OSError as e:
                self.logger.debug(f"Group frame listener on {interface}: {e}")
                time.sleep(self.config['interval'])

    # YUMI: added (deaf_timeout), see YUMI_PATCHES.md
    def has_ipv4(self, interface):
        """True when the interface holds an IPv4 address (connected)."""
        try:
            result = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev",
                                     interface], capture_output=True, text=True)
            return " inet " in result.stdout
        except (subprocess.SubprocessError, OSError):
            return False

    # YUMI: added (deaf_timeout), see YUMI_PATCHES.md
    def check_deafness(self):
        """Reconnect a WiFi adapter that stopped receiving broadcast/multicast.

        Seen on the RTL8188EUS (rtl8xxxu), C335 2026-11-10: associated, IP held,
        pings to the gateway fine, unicast received, but not one broadcast frame
        in minutes -- ARP requests for the host never arrived, so nothing on the
        network could reach it until the host itself transmitted. A plain
        reconnect brought broadcast reception back at once. Every other check
        here pings FROM the host and passes, so this runs on its own, whatever
        interface carries the default route.

        The verdict needs the adapter to have heard this network since the last
        reconnect: a network that falls silent costs one reconnect, never a
        loop of them."""
        timeout = self.config['deaf_timeout']
        if timeout <= 0 or not self.heard_group:
            return False
        silent = time.monotonic() - self.last_group_rx
        if silent < timeout:
            return False
        interface = self.get_wifi_interface()
        if interface is None or not self.has_ipv4(interface):
            return False
        self.logger.warning(
            f"{interface} heard no broadcast or multicast frame for {silent:.0f} s"
            f" while connected: other hosts can no longer find it on the"
            f" network (ARP). Reconnecting the WiFi.")
        self.heard_group = False
        self.restart_wifi(interface)
        return True

    # YUMI: added, see YUMI_PATCHES.md
    def live_target(self, target):
        """The address to ping now. With target "auto" it is the CURRENT default
        gateway: once NetworkManager has moved to another network the old gateway
        never answers again, and pinging it made sonar tear a working link down in
        a loop (bench 2026-10-15). Without a route, keep the last one."""
        if self.config['target'] != "auto":
            return target
        gateway = self.get_default_gateway()
        return gateway['gateway'] if gateway else target

    # YUMI: added, see YUMI_PATCHES.md
    def recover_until_reachable(self, target, interface):
        """Recover `interface` again and again until `target` answers; returns
        the number of attempts. recover_wifi (not plain restart_wifi): a wedged
        adapter (0 APs) gets its driver reloaded at once. Every
        soft_recoveries_before_reload attempts the reload is forced even though
        the adapter scans: a half-wedged dongle keeps its association and its
        route but transmits nothing, and soft reconnects alone never bring it
        back (bench 2026-09-06: 46 attempts, 50 min, fixed by a replug)."""
        n = self.config['soft_recoveries_before_reload']
        retry_count = 0
        used_retries = 0
        while True:
            target = self.live_target(target)
            if self.is_reachable(target):
                break
            retry_count += 1
            used_retries += 1
            force = used_retries % n == 0
            if force:
                self.logger.warning(
                    f"{used_retries} soft recoveries without a link: reloading the driver.")
            self.recover_wifi(interface, force_reload=force)
            self.logger.info("Waiting 10 seconds to re-establish the connection...")
            time.sleep(10)
            if retry_count == 3:
                self.logger.warning(
                    f"Reconnection attempt failed after {retry_count} tries."
                    f" Pausing for {self.config['interval']} seconds.")
                time.sleep(self.config['interval'])
                retry_count = 0
        return used_retries

    # YUMI: added, see YUMI_PATCHES.md
    def has_saved_wifi_profile(self):
        """True if NetworkManager knows at least one WiFi connection.

        Without a saved profile there is nothing to reconnect to: 'no
        default gateway' then simply means 'WiFi not configured yet' (bench
        pad, ethernet-only setup, first boot...). Escalating in that state
        restarts NetworkManager and rebinds the dongle in an endless loop,
        which is how perfectly healthy adapters end up wedged.
        """
        try:
            result = subprocess.run(
                ["nmcli", "-g", "TYPE", "connection", "show"],
                capture_output=True, text=True, timeout=10)
            return "802-11-wireless" in result.stdout
        except (subprocess.SubprocessError, OSError) as e:
            self.logger.debug(f"Could not list NM connections: {e}")
            return True   # fail open: better to attempt recovery than never

    LOSS_RE = re.compile(r'(\d+(?:\.\d+)?)% packet loss')

    # YUMI: added, replaces upstream ping_target, see YUMI_PATCHES.md
    def ping_loss(self, target, count):
        """Packet loss (percent) of `count` pings to the target, None if ping could not run.
        -W 1 bounds every lost reply to one second so a check on a dead link ends in ~count
        seconds instead of hanging."""
        try:
            result = subprocess.run(["ping", "-c", str(count), "-W", "1", target],
                                    capture_output=True, text=True)
        except Exception as e:
            self.logger.error(f"Error executing ping: {e}")
            return None
        m = self.LOSS_RE.search(result.stdout)
        if m is None:
            # no summary at all (unknown host, no route): nothing came back
            return 100
        loss = int(float(m.group(1)))
        if self.config['debug_log']:
            self.logger.debug(f"Ping to {target}: {loss}% loss")
        return loss

    # YUMI: added, see YUMI_PATCHES.md
    def is_reachable(self, target):
        """True while the packet loss to the target stays under loss_threshold percent."""
        loss = self.ping_loss(target, self.config['count'])
        self.last_loss = 100 if loss is None else loss
        return loss is not None and loss < self.config['loss_threshold']

    # YUMI: modified: loss streak, no-gateway recovery, deaf check, live gateway, see YUMI_PATCHES.md
    def run(self):
        if not self.config['enable']:
            self.logger.info("Sonar is disabled in the configuration. Exiting.")
            sys.exit(0)

        self.no_gateway_cycles = 0
        self.soft_recoveries = 0
        degraded_checks = 0
        self.last_loss = 0
        if self.config['deaf_timeout'] > 0:
            threading.Thread(target=self.listen_group_frames,
                             daemon=True).start()

        while True:
            self.check_deafness()
            gateway = self.get_default_gateway()

            if not gateway:
                self.handle_no_gateway()
                time.sleep(self.config['interval'])
                continue

            self.no_gateway_cycles = 0
            self.soft_recoveries = 0

            if not gateway['interface'].startswith(('wl', 'wlan', 'wlp')):
                self.logger.debug(f"No WiFi interface active for the default gateway."
                                  f" {gateway['interface']} is not a WiFi interface."
                                  f" Retrying...")
                time.sleep(self.config['interval'])
                continue

            target = self.config['target']
            if target == "auto":
                target = gateway['gateway']

            if not self.is_reachable(target):
                # The association and the IP may look fine while most frames are lost
                # (beacon loss on a marginal link): act once the loss stays above the
                # threshold for loss_streak consecutive checks, not on one bad burst.
                degraded_checks += 1
                if degraded_checks < self.config['loss_streak']:
                    self.logger.info(f"Link to {target} degraded: {self.last_loss}% loss "
                                     f"(check {degraded_checks}/{self.config['loss_streak']})")
                    time.sleep(self.config['interval'])
                    continue
                degraded_checks = 0
                restart_threshold = self.config['restart_threshold']
                self.logger.info(f"Connection lost – {target} is unreachable "
                                 f"({self.last_loss}% packet loss)!")
                self.logger.info(f"Waiting {restart_threshold} seconds before"
                                 f" attempting a restart.")
                time.sleep(restart_threshold)

                used_retries = self.recover_until_reachable(target, gateway['interface'])
                self.logger.info(f"Reconnected after {used_retries} attempts.")
            else:
                degraded_checks = 0

            time.sleep(self.config['interval'])


if __name__ == "__main__":
    try:
        start_arg_config = None
        if len(sys.argv) > 1:
            start_arg_config = sys.argv[1]
        daemon = SonarDaemon(start_arg_config)
        daemon.run()
    except KeyboardInterrupt:
        print("\nSonar daemon interrupted by user. Exiting.")
        sys.exit(0)
