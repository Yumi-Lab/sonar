"""check_deafness -- a WiFi adapter that stops receiving broadcast/multicast.
C335 2026-11-10 (RTL8188EUS, rtl8xxxu): associated, IP held, gateway pings fine,
but no broadcast frame for minutes, so ARP requests never arrived and the host was
unreachable from the network. A reconnect restored broadcast reception."""
import os
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
from test_ping import daemon, sonar  # noqa: E402


class Deafness(unittest.TestCase):
    def _deaf(self, d, silent):
        d.heard_group = True
        d.last_group_rx = 1000.
        return mock.patch.object(sonar.time, "monotonic", return_value=1000. + silent)

    def _check(self, d, silent, ipv4=True):
        with self._deaf(d, silent), \
                mock.patch.object(d, "get_wifi_interface", return_value="wlan0"), \
                mock.patch.object(d, "has_ipv4", return_value=ipv4), \
                mock.patch.object(d, "restart_wifi") as restart:
            acted = d.check_deafness()
        return acted, restart

    def test_reconnects_after_the_timeout_without_a_group_frame(self):
        acted, restart = self._check(daemon(deaf_timeout=180), 181)
        self.assertTrue(acted)
        restart.assert_called_once_with("wlan0")

    def test_quiet_less_than_the_timeout_is_fine(self):
        acted, restart = self._check(daemon(deaf_timeout=180), 120)
        self.assertFalse(acted)
        restart.assert_not_called()

    def test_on_by_default(self):
        # sonar.conf is never rewritten by an update: the default is what
        # reaches the machines already installed.
        self.assertEqual(daemon().config["deaf_timeout"], 180)
        acted, restart = self._check(daemon(), 181)
        self.assertTrue(acted)
        restart.assert_called_once_with("wlan0")

    def test_zero_turns_it_off(self):
        acted, restart = self._check(daemon(deaf_timeout=0), 10000)
        self.assertFalse(acted)
        restart.assert_not_called()

    def test_not_connected_is_left_to_the_other_checks(self):
        acted, restart = self._check(daemon(deaf_timeout=180), 181, ipv4=False)
        self.assertFalse(acted)
        restart.assert_not_called()

    def test_a_network_that_falls_silent_costs_one_reconnect_not_a_loop(self):
        d = daemon(deaf_timeout=180)
        acted, restart = self._check(d, 181)
        self.assertTrue(acted)
        # Nothing heard since the reconnect: no second verdict, however long.
        with mock.patch.object(sonar.time, "monotonic", return_value=1e9), \
                mock.patch.object(d, "get_wifi_interface", return_value="wlan0"), \
                mock.patch.object(d, "has_ipv4", return_value=True), \
                mock.patch.object(d, "restart_wifi") as again:
            self.assertFalse(d.check_deafness())
        again.assert_not_called()

    def test_never_heard_the_network_no_verdict(self):
        d = daemon(deaf_timeout=180)
        with mock.patch.object(sonar.time, "monotonic", return_value=1e9), \
                mock.patch.object(d, "restart_wifi") as restart:
            self.assertFalse(d.check_deafness())
        restart.assert_not_called()


class GroupFilter(unittest.TestCase):
    """The kernel filter, run here by a small classic-BPF interpreter."""
    OUTGOING, HOST, BROADCAST = 4, 0, 1

    def run_filter(self, pkttype, first_byte):
        prog, pc, a = sonar.GROUP_RX_FILTER, 0, 0
        while True:
            code, jt, jf, k = prog[pc]
            if code == 0x20:        # ld [SKF_AD_PKTTYPE]
                a = pkttype
            elif code == 0x30:      # ldb [0]
                a = first_byte
            elif code == 0x15:      # jeq
                pc += jt if a == k else jf
            elif code == 0x45:      # jset
                pc += jt if a & k else jf
            elif code == 0x06:      # ret
                return k
            pc += 1

    def test_keeps_inbound_broadcast_and_multicast(self):
        self.assertGreater(self.run_filter(self.BROADCAST, 0xff), 0)
        self.assertGreater(self.run_filter(2, 0x01), 0)

    def test_drops_unicast_and_own_frames(self):
        self.assertEqual(self.run_filter(self.HOST, 0x3c), 0)
        self.assertEqual(self.run_filter(self.OUTGOING, 0xff), 0)

    def test_program_packs_as_sock_filter(self):
        for ins in sonar.GROUP_RX_FILTER:
            self.assertEqual(len(struct.pack('HBBI', *ins)), 8)


if __name__ == "__main__":
    unittest.main()
