"""Checks the Proof data source against the installed cloud-init, with a stub of Proof's metadata service.

    python3 packaging/cloud-init/test_datasource.py

It needs cloud-init and the proof_cloudinit package importable, as on a VM or a CI runner with the .deb installed.
It changes nothing outside a temporary directory.
"""

import http.server
import json
import tempfile
import threading
import unittest
from unittest import mock

from cloudinit import distros, helpers, sources
from cloudinit.sources.helpers import ec2

from proof_cloudinit import DataSourceProof

UUID = "00112233-4455-6677-8899-aabbccddeeff"
META_DATA = {"uuid": UUID, "hostname": "web01", "public_keys": {"k": "ssh-ed25519 AAAA test"}}
NETWORK_DATA = {
    "links": [{"id": "eth0", "type": "phy", "ethernet_mac_address": "02:00:00:00:00:01"}],
    "networks": [{"id": "n0", "link": "eth0", "type": "ipv4", "ip_address": "192.0.2.10", "netmask": "255.255.255.0"}],
    "services": [],
}


class Stub(http.server.BaseHTTPRequestHandler):
    files = {
        "/openstack": b"latest",
        "/openstack/latest/meta_data.json": json.dumps(META_DATA).encode(),
        "/openstack/latest/network_data.json": json.dumps(NETWORK_DATA).encode(),
        "/openstack/latest/user_data": b"#cloud-config\n{}\n",
    }
    paths = []

    def do_GET(self):
        Stub.paths.append(self.path)
        body = self.files.get(self.path.rstrip("/"))
        self.send_response(200 if body is not None else 404)
        self.end_headers()
        self.wfile.write(body or b"")

    def log_message(self, *args):
        pass


class DataSourceProofTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Stub.paths.clear()
        self.tmp = tempfile.TemporaryDirectory()
        paths = helpers.Paths({"cloud_dir": self.tmp.name, "run_dir": self.tmp.name})
        self.distro = distros.fetch("debian")("debian", {}, paths)
        self.paths = paths

    def tearDown(self):
        self.tmp.cleanup()

    def source(self, cls=DataSourceProof.DataSourceProof, **cfg):
        sys_cfg = {"datasource_list": ["Proof"], "datasource": {"Proof": {"metadata_urls": [self.url], **cfg}}}
        return cls(sys_cfg, self.distro, self.paths)

    def test_reads_openstack_metadata_without_dhcp_or_ec2(self):
        ds = self.source()
        with mock.patch.object(ec2, "get_instance_metadata") as ec2_read, mock.patch(
            "cloudinit.sources.DataSourceOpenStack.EphemeralDHCPv4"
        ) as dhcp:
            self.assertTrue(ds.get_data())
        ec2_read.assert_not_called()
        dhcp.assert_not_called()
        self.assertEqual(UUID, ds.get_instance_id())
        self.assertEqual("web01", ds.get_hostname().hostname)
        self.assertEqual(["ssh-ed25519 AAAA test"], ds.get_public_ssh_keys())
        self.assertEqual(NETWORK_DATA, ds.network_json)
        # cloud-init names the link from the system's NIC with that MAC.
        with mock.patch("cloudinit.net.get_interfaces_by_mac", return_value={"02:00:00:00:00:01": "eth0"}):
            config = ds.network_config["config"]
        self.assertEqual(("eth0", "02:00:00:00:00:01"), (config[0]["name"], config[0]["mac_address"]))
        self.assertEqual("192.0.2.10", config[0]["subnets"][0]["address"])
        self.assertEqual(b"#cloud-config\n{}\n", ds.get_userdata_raw())
        self.assertFalse(any(p.startswith("/latest") or p.startswith("/ec2") for p in Stub.paths), Stub.paths)

    def test_single_entry_skips_detection_on_any_platform(self):
        ds = self.source()
        with mock.patch.object(ds, "ds_detect", return_value=False):
            self.assertTrue(ds.override_ds_detect())

    def test_defaults_come_after_the_image_config(self):
        ds = self.source(max_wait=7)
        self.assertEqual(7, ds.get_url_params().max_wait_seconds)
        self.assertEqual(["http://127.0.0.1:8169"], DataSourceProof.DataSourceProof(
            {"datasource_list": ["Proof"]}, self.distro, self.paths).ds_cfg["metadata_urls"])

    def test_no_answer_fails(self):
        ds = self.source(metadata_urls=["http://127.0.0.1:9"], max_wait=1, timeout=1)
        self.assertFalse(ds.get_data())

    def test_cloud_init_finds_it_by_name_in_both_stages(self):
        pkg = ["proof_cloudinit", "", "cloudinit.sources"]
        local = sources.list_sources(["Proof"], (sources.DEP_FILESYSTEM,), pkg)
        net = sources.list_sources(["Proof"], (sources.DEP_FILESYSTEM, sources.DEP_NETWORK), pkg)
        self.assertEqual([DataSourceProof.DataSourceProof], local)
        self.assertEqual([DataSourceProof.DataSourceProofNet], net)


if __name__ == "__main__":
    unittest.main(verbosity=2)
