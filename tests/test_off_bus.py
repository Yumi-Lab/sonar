"""report_off_bus / check_adapter_back -- a wedged USB adapter that the reset drops off the bus.
C235 2026-11-16 (RTL8188EUS 0bda:8179, rtl8xxxu): sonar unbound the wedged dongle, the kernel
reset failed, "usb 1-1: USB disconnect", bind ENODEV x3, then hours of a silent "No default
gateway" until the dongle was replugged. The same unbind/bind and module reload on the healthy
dongle reconnected in 4-6 s. sonar must say once that the adapter needs a replug, and say when
it is back. Fake sysfs tree; subprocess and sleep are mocked."""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
from test_ping import daemon, sonar  # noqa: E402


class OffBus(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        usb = os.path.join(self.root, "devices", "usb1", "1-1")
        self.usb = usb
        iface_dev = os.path.join(usb, "1-1:1.0")
        drv = os.path.join(self.root, "bus", "usb", "drivers", "rtl8xxxu")
        self.drv = drv
        mod = os.path.join(self.root, "module", "rtl8xxxu")
        for path in (iface_dev, drv, mod):
            os.makedirs(path)
        for name, value in (("idVendor", "0bda"), ("idProduct", "8179")):
            with open(os.path.join(usb, name), "w") as fh:
                fh.write(value + "\n")
        for name in ("unbind", "bind"):
            open(os.path.join(drv, name), "w").close()
        os.symlink(drv, os.path.join(iface_dev, "driver"))
        os.symlink(mod, os.path.join(drv, "module"))
        net = os.path.join(self.root, "class", "net", "wlan0")
        os.makedirs(net)
        os.makedirs(os.path.join(net, "wireless"))
        os.symlink(iface_dev, os.path.join(net, "device"))
        patcher = mock.patch.object(sonar, "SYS_CLASS_NET", os.path.join(self.root, "class", "net"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.d = daemon()

    def _drop_off_bus(self, *_):
        """The kernel reset fails: the USB device leaves the bus and bind gets ENODEV."""
        if os.path.exists(self.usb):
            shutil.rmtree(self.usb)
            os.remove(os.path.join(self.drv, "bind"))
            os.makedirs(os.path.join(self.drv, "bind"))  # writing to it raises an OSError

    def _reload(self, sleep):
        with mock.patch.object(sonar.time, "sleep", side_effect=sleep), \
                mock.patch.object(sonar.subprocess, "run"), \
                mock.patch.object(self.d.logger, "error") as error:
            self.d.reload_wifi_driver("wlan0")
        return error

    def test_healthy_adapter_comes_back_and_nothing_is_reported(self):
        error = self._reload(lambda *_: None)
        error.assert_not_called()
        self.assertIsNone(self.d.adapter_off_bus)

    def test_adapter_dropped_off_the_bus_is_reported_once_with_what_to_do(self):
        error = self._reload(self._drop_off_bus)
        error.assert_called_once()
        message = error.call_args[0][0]
        self.assertIn("1-1 (0bda:8179)", message)
        self.assertIn("Unplug it and plug it back in", message)
        self.assertEqual(self.d.adapter_off_bus, "1-1 (0bda:8179)")

    def test_adapter_back_is_logged_once_and_clears_the_state(self):
        self.d.adapter_off_bus = "1-1 (0bda:8179)"
        with mock.patch.object(self.d.logger, "info") as info:
            self.d.check_adapter_back()
            self.d.check_adapter_back()
        info.assert_called_once()
        self.assertIn("back as wlan0", info.call_args[0][0])
        self.assertIsNone(self.d.adapter_off_bus)

    def test_still_missing_adapter_stays_reported_and_quiet(self):
        self.d.adapter_off_bus = "1-1 (0bda:8179)"
        shutil.rmtree(os.path.join(self.root, "class", "net", "wlan0"))
        with mock.patch.object(self.d.logger, "info") as info:
            self.d.check_adapter_back()
        info.assert_not_called()
        self.assertEqual(self.d.adapter_off_bus, "1-1 (0bda:8179)")

    def test_built_in_adapter_has_no_usb_device(self):
        os.remove(os.path.join(self.usb, "idVendor"))
        self.assertIsNone(self.d.usb_device_of(
            os.path.join(self.root, "class", "net", "wlan0", "device")))


if __name__ == "__main__":
    unittest.main()
