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
            'tcp_fallback': cp.getboolean('sonar', 'tcp_fallback'),
            'tcp_check_host': cp.get('sonar', 'tcp_check_host'),
            'tcp_check_port': cp.getint('sonar', 'tcp_check_port')
        }

        port = self.config['tcp_check_port']
        if not 1 <= port <= 65535:
            self.logger.warning(f"tcp_check_port {port} is out of range"
                                f" (1-65535), falling back to 443.")
            self.config['tcp_check_port'] = 443

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
            try:
                subprocess.run(["systemctl", "restart",
                                "NetworkManager.service"], check=True)
                self.logger.info("NetworkManager service restarted.")
            except subprocess.CalledProcessError:
                self.logger.warning("Restarting NetworkManager failed.")
        else:
            self.logger.error("No active service found to restart WiFi"
                              " connection.")

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
        except (OSError, ValueError, OverflowError) as e:
            self.logger.debug(f"tcp_check {host}:{port} failed: {e}")
            return False

    def is_reachable(self, target):
        """Decide whether connectivity is up, robust to ICMP-filtered networks.

        Some networks — most notably iOS/Android personal hotspots — silently
        drop ICMP, so a failed ping does NOT mean the link is down. Restarting
        WiFi there would tear down a perfectly working connection. Fall back to
        a real TCP connection before declaring an outage: only when BOTH ICMP
        and TCP fail is the network considered actually down.
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

        while True:
            gateway = self.get_default_gateway()

            if not gateway:
                self.logger.warning("No default gateway found. Retrying...")
                time.sleep(self.config['interval'])
                continue

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
                    self.restart_wifi(gateway['interface'])
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
