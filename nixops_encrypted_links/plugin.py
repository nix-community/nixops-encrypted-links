import os.path
import nixops.plugins
from nixops.deployment import Deployment, DeploymentPlugin
from nixops.backends import MachineState, MachinePlugin


@nixops.plugins.hookimpl
def nixexprs():
    return [os.path.dirname(os.path.abspath(__file__)) + "/nix"]


@nixops.plugins.hookimpl
def machine_hook() -> MachinePlugin:

    from .lib import generate_vpn_key

    class EncryptedLinksMachinePlugin(MachinePlugin):

        def post_wait(self, m: MachineState) -> None:
            generate_vpn_key(m)

    return EncryptedLinksMachinePlugin()


@nixops.plugins.hookimpl
def deployment_hook() -> DeploymentPlugin:

    from .lib import mk_matrix

    class EncryptedLinksDeploymentPlugin(DeploymentPlugin):

        def physical_spec(self, d: Deployment):
            return mk_matrix(d)

    return EncryptedLinksDeploymentPlugin()
