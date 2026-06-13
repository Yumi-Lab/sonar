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

  If "auto" is set for the target, the default gateway (router IP) is determined
  automatically.

Note: If persistent_log is enabled, logs will be written to /var/log/sonar.log.
"""

import subprocess
import time
import configparser
import os
import re
import sys
import shutil
import socket
import logging


class SonarDaemon:
    """Sonar - A WiFi Keepalive Daemon"""

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
        self.logger.info(f"  dongle_recovery: {self.config['dongle_recovery']}")
        self.logger.info(f"  dongle_recovery_threshold: {self.config['dongle_recovery_threshold']}")
        self.logger.info(f"  tcp_fallback: {self.config['tcp_fallback']}")
        self.logger.info(f"  tcp_check_host: {self.config['tcp_check_host']}")
        self.logger.info(f"  tcp_check_port: {self.config['tcp_check_port']}")

        # Set debug level if needed
        if self.config['debug_log']:
            self.logger.setLevel(logging.DEBUG)
            self.logger.debug("Debug logging enabled.")

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
            'dongle_recovery': 'true',
            'dongle_recovery_threshold': '3',
            'tcp_fallback': 'true',
            'tcp_check_host': '1.1.1.1',
            'tcp_check_port': '443'
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
            'dongle_recovery': cp.getboolean('sonar', 'dongle_recovery'),
            'dongle_recovery_threshold':
                cp.getint('sonar', 'dongle_recovery_threshold'),
            'tcp_fallback': cp.getboolean('sonar', 'tcp_fallback'),
            'tcp_check_host': cp.get('sonar', 'tcp_check_host'),
            'tcp_check_port': cp.getint('sonar', 'tcp_check_port')
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
        pattern = r'default via (\S+).*? dev (\S+).*?src (\S+).*?metric (\d+)'

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

            # Sort matches by metric (ascending order)
            matches.sort(key=lambda x: int(x[3]))

            return {
                'gateway': matches[0][0],  # Gateway IP
                'interface': matches[0][1],  # Device name (e.g., wlan0)
                'src': matches[0][2],  # Source IP
                'metric': int(matches[0][3])  # Metric value
            }
        except Exception as e:
            self.logger.error(f"Error retrieving default gateway: {e}")
            return None

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
            return len([ln for ln in r.stdout.splitlines() if ln.strip()])
        except (subprocess.SubprocessError, OSError) as e:
            self.logger.debug(f"wifi_scan_count probe failed: {e}")
            return -1

    def recover_wifi(self, interface):
        """Escalating recovery for one interface, wedge-aware.

        1. soft reconnect (nmcli per-device, NM restart fallback)
        2. if the adapter then still sees ZERO APs -> it's wedged, reload the
           driver / rebind USB (reload_wifi_driver). This is the path that
           the old 'N consecutive no-gateway cycles' trigger never reached
           when a phantom gateway (flapping link, or a parasitic eth0) kept
           resetting the counter — the wedge is detected directly instead.
        """
        self.restart_wifi(interface)
        time.sleep(5)
        if not self.config['dongle_recovery']:
            return
        n = self.wifi_scan_count(interface)
        if n == 0:
            self.logger.warning(f"{interface} sees 0 APs after restart — "
                                f"adapter wedged, reloading driver.")
            self.reload_wifi_driver(interface)
            time.sleep(5)
        elif n > 0:
            self.logger.debug(f"{interface} sees {n} APs — adapter scans fine,"
                              f" not a wedge (target AP may just be absent).")

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

    def ping_target(self, target, count):
        try:
            result = subprocess.run(["ping", "-c", str(count), target],
                                    capture_output=True, text=True)
            if result.returncode != 0:
                return False

            if self.config['debug_log']:
                lines = result.stdout.splitlines()
                summary = lines[-1]
                self.logger.debug(f"Ping to {target} successful: {summary}")

            return True
        except Exception as e:
            self.logger.error(f"Error executing ping: {e}")
            return False

    def tcp_check(self, host, port, timeout=3):
        """Return True if a TCP connection to host:port can be established."""
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True
        except OSError:
            return False

    def is_reachable(self, target):
        """Decide whether connectivity is up, robust to ICMP-filtered networks.

        Many phone hotspots (iOS/Android) silently drop ICMP, so a failed ping
        does NOT mean the link is down — tearing WiFi down there would break a
        perfectly working tethered connection. So fall back to a real TCP
        connection before declaring an outage: only when BOTH ICMP and TCP fail
        do we consider the network actually down.
        """
        if self.ping_target(target, self.config['count']):
            return True

        if self.config['tcp_fallback']:
            host = self.config['tcp_check_host']
            port = self.config['tcp_check_port']
            if self.tcp_check(host, port):
                self.logger.debug(f"ICMP to {target} failed but TCP "
                                  f"{host}:{port} succeeded — link is up "
                                  f"(ICMP filtered). Not an outage.")
                return True

        return False

    def run(self):
        if not self.config['enable']:
            self.logger.info("Sonar is disabled in the configuration. Exiting.")
            sys.exit(0)

        no_gateway_cycles = 0
        recovery_rounds = 0

        while True:
            gateway = self.get_default_gateway()

            if not gateway:
                # WiFi is fully down (no default route). Plain keepalive can
                # do nothing here, so after a few cycles escalate recovery on
                # the detected WiFi interface: NetworkManager restart first,
                # then a hardware reload if the adapter is wedged (a USB
                # dongle that no longer scans needs re-initialising).
                no_gateway_cycles += 1
                self.logger.warning(f"No default gateway found "
                                    f"(cycle {no_gateway_cycles}). Retrying...")

                # Exponential backoff between recovery rounds: if recovery
                # didn't bring a gateway back, the cause is external (AP off,
                # no internet on the bench...) and hammering NM restarts +
                # USB rebinds every few cycles only ends up wedging the
                # dongle for good.
                threshold = self.config['dongle_recovery_threshold'] * (
                    2 ** min(recovery_rounds, 5))
                if self.config['dongle_recovery'] and \
                        no_gateway_cycles >= threshold:
                    wifi_if = self.get_wifi_interface()
                    if wifi_if and not self.has_saved_wifi_profile():
                        self.logger.info(
                            "No saved WiFi profile — nothing to reconnect "
                            "to, skipping recovery escalation.")
                    elif wifi_if:
                        self.logger.info(f"WiFi down for {no_gateway_cycles} "
                                         f"cycles – escalating recovery on "
                                         f"{wifi_if}.")
                        self.recover_wifi(wifi_if)
                        recovery_rounds += 1
                    no_gateway_cycles = 0

                time.sleep(self.config['interval'])
                continue

            no_gateway_cycles = 0
            recovery_rounds = 0

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
                restart_threshold = self.config['restart_threshold']
                self.logger.info(f"Connection lost – {target} is unreachable!")
                self.logger.info(f"Waiting {restart_threshold} seconds before"
                                 f" attempting a restart.")
                time.sleep(restart_threshold)

                retry_count = 0
                used_retries = 0
                # Repeat until connectivity is restored (ICMP or TCP)
                while not self.is_reachable(target):
                    retry_count += 1
                    used_retries += 1
                    # recover_wifi (not plain restart_wifi): if the adapter is
                    # wedged it sees 0 APs and gets its driver reloaded. The
                    # old restart_wifi-only loop here is exactly where a wedged
                    # dongle with a phantom gateway spun forever on NM restarts
                    # without ever reloading the driver.
                    self.recover_wifi(gateway['interface'])
                    self.logger.info("Waiting 10 seconds to re-establish the connection...")
                    time.sleep(10)
                    if retry_count == 3:
                        self.logger.warning(
                            f"Reconnection attempt failed after {retry_count} tries."
                            f" Pausing for {self.config['interval']} seconds.")
                        time.sleep(self.config['interval'])
                        retry_count = 0

                self.logger.info(f"Reconnected after {used_retries} attempts.")

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
