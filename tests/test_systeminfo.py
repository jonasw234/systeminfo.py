#!/usr/bin/env python3
import os
import re
import subprocess
import unittest


class TestWindows10(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proc = subprocess.run(
            [
                f"{os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'systeminfo', 'systeminfo.py')}",
                "-p",
                f"{os.path.dirname(os.path.realpath(__file__))}",
            ],
            capture_output=True,
        )
        cls._stdout = proc.stdout.decode("utf-8")

    def test_host_name(self):
        match = re.search(r"Host Name:\s+SPIDERMAN", self._stdout)
        self.assertIsNotNone(match, msg="Host Name incorrect")

    def test_os_name(self):
        match = re.search(
            r"OS Name:\s+Microsoft Windows 10 Enterprise Evaluation", self._stdout
        )
        self.assertIsNotNone(match, msg="OS Name incorrect")

    def test_os_version(self):
        match = re.search(
            r"OS Version:\s+Windows 10 Enterprise Evaluation N/A Build 18363",
            self._stdout,
        )
        self.assertIsNotNone(match, msg="OS Version incorrect")

    def test_os_build_type(self):
        match = re.search(r"OS Build Type:\s+Multiprocessor Free", self._stdout)
        self.assertIsNotNone(match, msg="OS Build Type incorrect")

    def test_registered_owner(self):
        match = re.search(r"Registered Owner:\s+Peter Parker", self._stdout)
        self.assertIsNotNone(match, msg="Registered Owner incorrect")

    def test_product_id(self):
        match = re.search(r"Product ID:\s+00329-20000-00001-AA517", self._stdout)
        self.assertIsNotNone(match, msg="Product ID incorrect")

    def test_original_install_date(self):
        match = re.search(
            r"Original Install Date:\s+25-03-2020, 06:21:26", self._stdout
        )
        self.assertIsNotNone(match, msg="Original Install Date incorrect")

    def test_system_manufacturer(self):
        match = re.search(r"System Manufacturer:\s+innotek GmbH", self._stdout)
        self.assertIsNotNone(match, msg="System Manufacturer incorrect")

    def test_system_model(self):
        match = re.search(r"System Model:\s+VirtualBox", self._stdout)
        self.assertIsNotNone(match, msg="System Model incorrect")

    def test_system_type(self):
        match = re.search(r"System Type:\s+x64-based PC", self._stdout)
        self.assertIsNotNone(match, msg="System Type incorrect")

    def test_processors(self):
        match = re.search(
            r"\[01\]: Intel64 Family 6 Model 158 Stepping 13, GenuineIntel",
            self._stdout,
        )
        self.assertIsNotNone(match, msg="Processor(s) incorrect")

    def test_bios_version(self):
        match = re.search(
            r"BIOS Version:\s+innotek GmbH VirtualBox, 12/01/2006", self._stdout
        )
        self.assertIsNotNone(match, msg="BIOS Version incorrect")

    def test_windows_directory(self):
        match = re.search(r"Windows Directory:\s+C:\\Windows", self._stdout)
        self.assertIsNotNone(match, msg="Windows Directory incorrect")

    def test_system_directory(self):
        match = re.search(r"System Directory:\s+C:\\Windows\\System32", self._stdout)
        self.assertIsNotNone(match, msg="System Directory incorrect")

    def test_boot_device(self):
        match = re.search(r"Boot Device:\s+\\Device\\HarddiskVolume1", self._stdout)
        self.assertIsNotNone(match, msg="Boot Device incorrect")

    def test_system_locale(self):
        match = re.search(r"System Locale:\s+en-DE;Germany", self._stdout)
        self.assertIsNotNone(match, msg="System Locale incorrect")

    def test_time_zone(self):
        match = re.search(
            r"Time Zone:\s+\(UTC-08:00\) Pacific Time \(US & Canada\)", self._stdout
        )
        self.assertIsNotNone(match, msg="OS Version incorrect")

    def test_page_file_locations(self):
        match = re.search(r"Page File Location\(s\):\s+C:\\pagefile\.sys", self._stdout)
        self.assertIsNotNone(match, msg="Page File Location(s) incorrect")

    def test_domain(self):
        match = re.search(r"Domain:\s+MARVEL\.local", self._stdout)
        self.assertIsNotNone(match, msg="Domain incorrect")

    def test_hotfixs(self):
        match = re.search(r"Hotfix\(s\):\s+6 Hotfix\(s\) Installed.", self._stdout)
        self.assertIsNotNone(match, msg="Hotfix(s) incorrect")

    def test_network_cards(self):
        match = re.search(r"\[01\]: 192\.168\.56\.103", self._stdout)
        self.assertIsNotNone(match, msg="OS Version incorrect")


if __name__ == "__main__":
    unittest.main()
