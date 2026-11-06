"""cloud-init data source for Proof's instance metadata.

Proof serves OpenStack's metadata format on loopback, from the VM's Hyper-V host over a Hyper-V socket. This is
cloud-init's own OpenStack data source with two differences, both because the metadata is on loopback:

- No temporary DHCP lease before reading it. The metadata is read in cloud-init's first stage on any network, so the
  static configuration in network_data.json is written before the network starts.
- No read of EC2's metadata from 169.254.169.254, which cloud-init's OpenStack reader makes as well. Nothing answers
  there, so it would send packets to the default gateway, wait for them to time out and mark the boot degraded.

Enable it in the image, in /etc/cloud/cloud.cfg.d/:

    datasource_pkg_list: [proof_cloudinit]
    datasource_list: [Proof]
"""

import logging

from cloudinit import dmi, sources, util
from cloudinit.sources import DataSourceOpenStack
from cloudinit.sources.helpers import openstack

LOG = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "metadata_urls": ["http://127.0.0.1:8169"],
    # The host can be briefly unavailable, for example while proof-metadata starts. Without a wait, cloud-init asks once.
    "max_wait": 120,
}


class _Reader(openstack.MetadataReader):
    def _read_ec2_metadata(self):
        return {}


class DataSourceProof(DataSourceOpenStack.DataSourceOpenStack):
    """Found in cloud-init's first stage, before the network."""

    dsname = "Proof"

    def __init__(self, sys_cfg, distro, paths):
        super().__init__(sys_cfg, distro, paths)
        # What the image sets comes first.
        self.ds_cfg = util.mergemanydict([self.ds_cfg, DEFAULT_CONFIG])

    def ds_detect(self):
        # Asked only when the data source list has other entries, since with Proof alone cloud-init skips detection.
        # A Hyper-V VM, which is all Proof serves.
        return dmi.read_dmi_data("system-manufacturer") == "Microsoft Corporation" and dmi.read_dmi_data(
            "system-product-name"
        ) == "Virtual Machine"

    def _crawl_metadata(self):
        if not self.wait_for_metadata_service():
            raise sources.InvalidMetaDataException("Proof's metadata service did not answer")

        url_params = self.get_url_params()
        reader = _Reader(
            self.metadata_address,
            ssl_details=self.ssl_details,
            retries=url_params.num_retries,
            timeout=url_params.timeout_seconds,
        )
        try:
            return reader.read_v2()
        except openstack.NonReadable as e:
            raise sources.InvalidMetaDataException(str(e)) from e
        except (openstack.BrokenMetadata, IOError) as e:
            raise sources.InvalidMetaDataException("Broken metadata from %s" % self.metadata_address) from e


class DataSourceProofNet(DataSourceProof):
    """Tried again in cloud-init's network stage, if the host could not be reached in the first."""


datasources = [
    (DataSourceProof, (sources.DEP_FILESYSTEM,)),
    (DataSourceProofNet, (sources.DEP_FILESYSTEM, sources.DEP_NETWORK)),
]


def get_datasource_list(depends):
    return sources.list_from_depends(depends, datasources)
