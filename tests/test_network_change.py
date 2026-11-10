"""Recovery after the WiFi moved to another network, and the scan probe (no network, mocked).
Bench 2026-10-15: MIFI-6BDD vanished, NetworkManager joined YUMi_IoT at once (lease, gateway
192.168.72.1 answering), but sonar kept pinging the old gateway 192.168.100.1, tore the working
link down every ~30 s, then read "0 APs" right after a NetworkManager restart and reset the
RTL8188EUS, which fell off the USB bus until it was replugged."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
from test_ping import daemon, sonar  # noqa: E402

OLD_GW, NEW_GW = "192.168.100.1", "192.168.72.1"


class NetworkChange(unittest.TestCase):
    def test_follows_the_new_gateway_instead_of_tearing_the_link_down(self):
        d = daemon(interval=1, dongle_recovery="true")
        pings = []

        def reachable(target):
            pings.append(target)
            if pings.count(OLD_GW) > 3:
                raise AssertionError("still pinging the gateway of the network it left")
            return target == NEW_GW

        new_route = {"gateway": NEW_GW, "interface": "wlan0", "src": "192.168.72.22", "metric": 600}
        with mock.patch.object(d, "get_default_gateway", return_value=new_route), \
                mock.patch.object(d, "is_reachable", side_effect=reachable), \
                mock.patch.object(d, "recover_wifi", return_value=False) as recover, \
                mock.patch.object(sonar.time, "sleep"):
            self.assertEqual(d.recover_until_reachable(OLD_GW, "wlan0"), 0)
        recover.assert_not_called()

    def test_a_fixed_target_is_kept(self):
        d = daemon(interval=1, target="1.1.1.1")
        with mock.patch.object(d, "get_default_gateway") as route:
            self.assertEqual(d.live_target("1.1.1.1"), "1.1.1.1")
        route.assert_not_called()

    def test_no_route_keeps_the_last_target(self):
        d = daemon(interval=1)
        with mock.patch.object(d, "get_default_gateway", return_value=None):
            self.assertEqual(d.live_target(OLD_GW), OLD_GW)


class ScanProbe(unittest.TestCase):
    def test_failed_scan_is_unknown_not_a_wedge(self):
        d = daemon()
        with mock.patch("subprocess.run", return_value=mock.Mock(stdout="", returncode=10)):
            self.assertEqual(d.wifi_scan_count("wlan0"), -1)
        listing = "AA\\:BB\\:CC\\:DD\\:EE\\:01\nAA\\:BB\\:CC\\:DD\\:EE\\:02\n"
        with mock.patch("subprocess.run", return_value=mock.Mock(stdout=listing, returncode=0)):
            self.assertEqual(d.wifi_scan_count("wlan0"), 2)


class SavedNetworkAbsent(unittest.TestCase):
    """C335 2026-11-09: carried away from its MIFI, the machine scanned the 5
    neighbouring networks and sonar reloaded the driver 25 times anyway."""

    def nmcli(self, saved_ssid, visible):
        def run(cmd, **kw):
            if cmd[:6] == ["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"]:
                return mock.Mock(stdout="MIFI-6BDD:802-11-wireless\nWired:802-3-ethernet\n",
                                 returncode=0)
            if cmd[:3] == ["nmcli", "-g", "802-11-wireless.ssid"]:
                return mock.Mock(stdout=saved_ssid + "\n", returncode=0)
            if cmd[:5] == ["nmcli", "-t", "-f", "SSID", "device"]:
                return mock.Mock(stdout="".join(v + "\n" for v in visible), returncode=0)
            return mock.Mock(stdout="", returncode=0)
        return run

    def recover(self, saved_ssid, visible, aps):
        d = daemon(dongle_recovery="true")
        with mock.patch("subprocess.run", side_effect=self.nmcli(saved_ssid, visible)), \
                mock.patch.object(d, "restart_wifi"), \
                mock.patch.object(d, "wifi_scan_count", return_value=aps), \
                mock.patch.object(d, "reload_wifi_driver") as reload, \
                mock.patch.object(sonar.time, "sleep"):
            d.recover_wifi("wlan0", force_reload=True)
        return reload

    def test_no_reload_when_the_saved_network_is_out_of_range(self):
        reload = self.recover("MIFI-6BDD", ["Neighbour", "ChinaNet-x", "Other"], 3)
        reload.assert_not_called()

    def test_reload_when_the_saved_network_is_there_but_no_lease(self):
        reload = self.recover("MIFI-6BDD", ["Neighbour", "MIFI-6BDD"], 2)
        reload.assert_called_once_with("wlan0")

    def test_reload_when_the_adapter_sees_nothing(self):
        reload = self.recover("MIFI-6BDD", [], 0)
        reload.assert_called_once_with("wlan0")

    def test_unknown_visibility_keeps_the_old_behaviour(self):
        d = daemon(dongle_recovery="true")
        with mock.patch("subprocess.run", side_effect=OSError("no nmcli")), \
                mock.patch.object(d, "restart_wifi"), \
                mock.patch.object(d, "wifi_scan_count", return_value=4), \
                mock.patch.object(d, "reload_wifi_driver") as reload, \
                mock.patch.object(sonar.time, "sleep"):
            d.recover_wifi("wlan0", force_reload=True)
        reload.assert_called_once_with("wlan0")


if __name__ == "__main__":
    unittest.main()
