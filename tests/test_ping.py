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
