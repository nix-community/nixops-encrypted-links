from collections import defaultdict
from typing import (
    Callable,
    Dict,
    Optional,
    TextIO,
    Set,
    List,
    DefaultDict,
    Any,
    Tuple,
    ValuesView,
    Union,
    cast,
)

import nixops.resources
from nixops.backends import MachineState, MachineDefinition, MachineOptions
from nixops.deployment import Deployment, is_machine
from typing import Dict


def generate_vpn_key(s: MachineState):
    self = s

    key_missing = False
    try:
        self.run_command("test -f /root/.ssh/id_charon_vpn")
    except nixops.ssh_util.SSHCommandFailed:
        key_missing = True

    # TODO: Make the public_vpn_key attr something that's handled by this plugin as a resource
    if self.public_vpn_key and not key_missing:
        return

    (private, public) = nixops.util.create_key_pair(
        key_name="NixOps VPN key of {0}".format(self.name)
    )
    f = open(self.depl.tempdir + "/id_vpn-" + self.name, "w+")
    f.write(private)
    f.seek(0)
    res = self.run_command(
        "umask 077 && mkdir -p /root/.ssh &&" " cat > /root/.ssh/id_charon_vpn",
        check=False,
        stdin=f,
    )
    if res != 0:
        raise Exception("unable to upload VPN key to ‘{0}’".format(self.name))
    self.public_vpn_key = public


class EncryptedLinksDefinition(MachineDefinition):
    encryptedLinksTo: Set[str]


def index_to_private_ip(index: int) -> str:
    n = 105 + index / 256
    assert n <= 255
    return "192.168.{0}.{1}".format(n, index % 256)


def to_encrypted_links_defn(d: Optional[MachineDefinition]) -> EncryptedLinksDefinition:
    if d:
        e = EncryptedLinksDefinition(d.name, d.resource_eval)
        e.encryptedLinksTo = d.resource_eval['encryptedLinksTo']
        return e
    else:
        raise TypeError('defn was None')


def mk_matrix(d: Deployment) -> Dict[str, List[Dict[Tuple[str, ...], Any]]]:
    self = d

    active_machines = self.active_machines
    active_resources = self.active_resources

    attrs_per_resource: Dict[str, List[Dict[Tuple[str, ...], Any]]] = {
        m.name: [] for m in active_resources.values()
    }

    hosts: DefaultDict[str, DefaultDict[str, List[str]]] = defaultdict(
        lambda: defaultdict(list)
    )

    kernel_modules: Dict[str, Set[str]] = {
        m.name: set() for m in active_machines.values()
    }

    authorized_keys: Dict[str, List[str]] = {
        m.name: [] for m in active_machines.values()
    }

    trusted_interfaces: Dict[str, Set[str]] = {
        m.name: set() for m in active_machines.values()
    }

    def do_machine(m: nixops.backends.MachineState) -> None:
        defn = to_encrypted_links_defn(m.defn)

        attrs_list = attrs_per_resource[m.name]

        # Emit configuration to realise encrypted peer-to-peer links.
        for r2 in active_resources.values():
            ip = m.address_to(r2)
            if ip:
                hosts[m.name][ip] += [r2.name, r2.name + "-unencrypted"]

        # Always use the encrypted/unencrypted suffixes for aliases rather
        # than for the canonical name!
        hosts[m.name]["127.0.0.1"].append(m.name + "-encrypted")

        for m2_name in defn.encryptedLinksTo:

            if m2_name not in active_machines:
                raise Exception(
                    "‘deployment.encryptedLinksTo’ in machine ‘{0}’ refers to an unknown machine ‘{1}’".format(
                        m.name, m2_name
                    )
                )
            m2 = active_machines[m2_name]

            # Don't create two tunnels between a pair of machines.
            if (
                m.name
                in to_encrypted_links_defn(self._machine_definition_for_required(m2.name)).encryptedLinksTo
                and m.name >= m2.name
            ):
                continue
            if not m.index:
                raise ValueError("Index was: {type(m.index)}")
            if not m2.index:
                raise ValueError("Index was: {type(m.index)}")
            local_ipv4 = index_to_private_ip(m.index)
            remote_ipv4 = index_to_private_ip(m2.index)
            local_tunnel = 10000 + m2.index
            remote_tunnel = 10000 + m.index
            attrs_list.append(
                {
                    ("networking", "p2pTunnels", "ssh", m2.name): {
                        "target": "{0}-unencrypted".format(m2.name),
                        "targetPort": m2.ssh_port,
                        "localTunnel": local_tunnel,
                        "remoteTunnel": remote_tunnel,
                        "localIPv4": local_ipv4,
                        "remoteIPv4": remote_ipv4,
                        "privateKey": "/root/.ssh/id_charon_vpn",
                    }
                }
            )

            # FIXME: set up the authorized_key file such that ‘m’
            # can do nothing more than create a tunnel.
            if m.public_vpn_key:
                authorized_keys[m2.name].append(m.public_vpn_key)
            kernel_modules[m.name].add("tun")
            kernel_modules[m2.name].add("tun")
            hosts[m.name][remote_ipv4] += [m2.name, m2.name + "-encrypted"]
            hosts[m2.name][local_ipv4] += [m.name, m.name + "-encrypted"]
            trusted_interfaces[m.name].add("tun" + str(local_tunnel))
            trusted_interfaces[m2.name].add("tun" + str(remote_tunnel))

        private_ipv4 = m.private_ipv4
        if private_ipv4:
            attrs_list.append({("networking", "privateIPv4"): private_ipv4})
        public_ipv4 = m.public_ipv4
        if public_ipv4:
            attrs_list.append({("networking", "publicIPv4"): public_ipv4})

        public_vpn_key = m.public_vpn_key
        if public_vpn_key:
            attrs_list.append({("networking", "vpnPublicKey"): public_vpn_key})

    for m in active_machines.values():
        do_machine(m)

    def emit_resource(r: nixops.resources.ResourceState) -> None:
        config = attrs_per_resource[r.name]
        if is_machine(r):
            if authorized_keys[r.name]:
                config.append(
                    {
                        ("users", "extraUsers", "root"): {
                            ("openssh", "authorizedKeys", "keys"): authorized_keys[
                                r.name
                            ]
                        },
                        ("services", "openssh"): {
                            "extraConfig": "PermitTunnel yes\n"
                        },
                    }
                )

            config.append(
                {
                    ("boot", "kernelModules"): list(kernel_modules[r.name]),
                    ("networking", "firewall"): {
                        "trustedInterfaces": list(trusted_interfaces[r.name])
                    },
                }
            )


            # Add SSH public host keys for all machines in network.
            for m2 in active_machines.values():
                if hasattr(m2, "public_host_key") and m2.public_host_key:
                    # Using references to files in same tempdir for now, until NixOS has support
                    # for adding the keys directly as string. This way at least it is compatible
                    # with older versions of NixOS as well.
                    # TODO: after reasonable amount of time replace with string option
                    config.append(
                        {
                            ("services", "openssh", "knownHosts", m2.name): {
                                "hostNames": [
                                    m2.name + "-unencrypted",
                                    m2.name + "-encrypted",
                                ],
                            }
                        }
                    )

    for r in active_resources.values():
        emit_resource(r)

    return attrs_per_resource
