import os.path
import nixops.plugins
from nixops.deployment import Deployment
from nixops.backends import MachineState
from nixops.plugins import Plugin, MachineHooks, DeploymentHooks

from .lib import generate_vpn_key
from .lib import mk_matrix


class EncryptedLinksMachineHooks(MachineHooks):

    def post_wait(self, m: MachineState) -> None:
        generate_vpn_key(m)


class EncryptedLinksDeploymentHooks(DeploymentHooks):

    def physical_spec(self, d: Deployment):
        return mk_matrix(d)


class NixopsEncryptedLinksPlugin(Plugin):

    def __init__(self):
        self._deployment_hooks = EncryptedLinksDeploymentHooks()
        self._machine_hooks = EncryptedLinksMachineHooks()

    def deployment_hooks(self) -> EncryptedLinksDeploymentHooks:
        return self._deployment_hooks

    def machine_hooks(self) -> EncryptedLinksMachineHooks:
        return self._machine_hooks

    @staticmethod
    def nixexprs():
        return [os.path.dirname(os.path.abspath(__file__)) + "/nix"]

    @staticmethod
    def load():
        return []


@nixops.plugins.hookimpl
def plugin():
    return NixopsEncryptedLinksPlugin()
