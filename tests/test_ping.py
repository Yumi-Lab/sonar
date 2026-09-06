"""is_reachable — packet loss against loss_threshold (no network, subprocess mocked)."""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sonar  # noqa: E402


def ping_output(sent, received):
    loss = 100 - int(100 * received / sent)
    return ("PING x (1.2.3.4) 56(84) bytes of data.\n\n--- x ping statistics ---\n"
            "%d packets transmitted, %d received, %d%% packet loss, time 3005ms\n" % (sent, received, loss))


def daemon(**options):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "sonar.conf")
    with open(path, "w") as f:
        f.write("[sonar]\nenable: true\n" + "".join("%s: %s\n" % kv for kv in options.items()))
    return sonar.SonarDaemon(path)


class Reachable(unittest.TestCase):
    def _run(self, output, returncode=0):
        return mock.Mock(stdout=output, returncode=returncode)

    def test_legacy_threshold_fails_only_when_nothing_answers(self):
        s = daemon(count=4)
        self.assertEqual(s.config["loss_threshold"], 100)
        with mock.patch("subprocess.run", return_value=self._run(ping_output(4, 1), 0)):
            self.assertTrue(s.is_reachable("1.2.3.4"))
            self.assertEqual(s.last_loss, 75)
        with mock.patch("subprocess.run", return_value=self._run(ping_output(4, 0), 1)):
            self.assertFalse(s.is_reachable("1.2.3.4"))

    def test_lower_threshold_catches_a_lossy_link(self):
        s = daemon(count=4, loss_threshold=50)
        with mock.patch("subprocess.run", return_value=self._run(ping_output(4, 3))):
            self.assertTrue(s.is_reachable("1.2.3.4"))     # 25 % loss
        with mock.patch("subprocess.run", return_value=self._run(ping_output(4, 2))):
            self.assertFalse(s.is_reachable("1.2.3.4"))    # 50 % loss
            self.assertEqual(s.last_loss, 50)

    def test_ping_failure_or_no_summary_is_unreachable(self):
        s = daemon(count=2)
        with mock.patch("subprocess.run", side_effect=OSError("no ping")):
            self.assertFalse(s.is_reachable("1.2.3.4"))
        with mock.patch("subprocess.run", return_value=self._run("ping: unknown host\n", 2)):
            self.assertFalse(s.is_reachable("nowhere"))
            self.assertEqual(s.last_loss, 100)

    def test_ping_command_bounds_each_lost_reply(self):
        s = daemon(count=3)
        with mock.patch("subprocess.run", return_value=self._run(ping_output(3, 3))) as run:
            s.is_reachable("1.2.3.4")
        self.assertEqual(run.call_args[0][0], ["ping", "-c", "3", "-W", "1", "1.2.3.4"])

    def test_streak_is_at_least_one(self):
        self.assertEqual(daemon(loss_streak=0).config["loss_streak"], 1)
        self.assertEqual(daemon(loss_streak=3).config["loss_streak"], 3)


if __name__ == "__main__":
    unittest.main()


class HalfWedgedDongle(unittest.TestCase):
    """Associated, "connected", scanning fine — but never a lease: after
    soft_recoveries_before_reload soft reconnects without a gateway the driver is
    reloaded even though APs are visible (bench 2026-09-06, three such drops)."""

    def make(self, **options):
        d = daemon(interval=1, dongle_recovery="true", dongle_recovery_threshold=1,
                   soft_recoveries_before_reload=3, **options)
        d.no_gateway_cycles = 0
        d.soft_recoveries = 0
        return d

    def test_reload_after_three_soft_recoveries(self):
        d = self.make()
        with mock.patch.object(d, "get_wifi_interface", return_value="wlan0"), \
                mock.patch.object(d, "has_saved_wifi_profile", return_value=True), \
                mock.patch.object(d, "restart_wifi") as restart, \
                mock.patch.object(d, "wifi_scan_count", return_value=7), \
                mock.patch.object(d, "reload_wifi_driver") as reload, \
                mock.patch.object(sonar.time, "sleep"):
            self.assertFalse(d.handle_no_gateway())
            self.assertFalse(d.handle_no_gateway())
            reload.assert_not_called()
            self.assertTrue(d.handle_no_gateway(), "third soft failure escalates")
            reload.assert_called_once_with("wlan0")
            self.assertEqual(restart.call_count, 3)
            self.assertEqual(d.soft_recoveries, 0, "the escalation counter restarts after a reload")

    def test_a_wedged_adapter_reloads_at_once(self):
        d = self.make()
        with mock.patch.object(d, "get_wifi_interface", return_value="wlan0"), \
                mock.patch.object(d, "has_saved_wifi_profile", return_value=True), \
                mock.patch.object(d, "restart_wifi"), \
                mock.patch.object(d, "wifi_scan_count", return_value=0), \
                mock.patch.object(d, "reload_wifi_driver") as reload, \
                mock.patch.object(sonar.time, "sleep"):
            self.assertTrue(d.handle_no_gateway())
            reload.assert_called_once_with("wlan0")

    def test_gateway_back_resets_the_escalation(self):
        d = self.make()
        d.soft_recoveries = 2
        # the main loop resets both counters once a gateway is seen again
        d.no_gateway_cycles = 0
        d.soft_recoveries = 0
        with mock.patch.object(d, "get_wifi_interface", return_value="wlan0"), \
                mock.patch.object(d, "has_saved_wifi_profile", return_value=True), \
                mock.patch.object(d, "restart_wifi"), \
                mock.patch.object(d, "wifi_scan_count", return_value=7), \
                mock.patch.object(d, "reload_wifi_driver") as reload, \
                mock.patch.object(sonar.time, "sleep"):
            d.handle_no_gateway()
            reload.assert_not_called()

    def test_option_is_at_least_one(self):
        d = daemon(soft_recoveries_before_reload=0)
        self.assertEqual(d.config["soft_recoveries_before_reload"], 1)


class UnreachableGateway(unittest.TestCase):
    """Route present, gateway silent (half-wedged dongle): the recovery loop must escalate to a
    driver reload every soft_recoveries_before_reload attempts, not spin on nmcli forever
    (bench 2026-09-06: 46 soft attempts, 50 minutes, fixed by replugging the dongle)."""

    def test_every_third_attempt_reloads_the_driver(self):
        d = daemon(interval=1, dongle_recovery="true", soft_recoveries_before_reload=3)
        answers = [False] * 6 + [True]
        with mock.patch.object(d, "is_reachable", side_effect=answers), \
                mock.patch.object(d, "recover_wifi", return_value=False) as recover, \
                mock.patch.object(sonar.time, "sleep"):
            self.assertEqual(d.recover_until_reachable("1.2.3.4", "wlan0"), 6)
        forced = [c.kwargs.get("force_reload") for c in recover.call_args_list]
        self.assertEqual(forced, [False, False, True, False, False, True])
