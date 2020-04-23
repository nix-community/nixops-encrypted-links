{ config, pkgs, lib, utils, ... }:

let
  inherit (lib) types;

  cfg = config.deployment.encryptedLinksTo;

in {
  options = {

    deployment.encryptedLinksTo = lib.mkOption {
      default = [];
      type = types.listOf types.str;
      description = ''
        NixOps will set up an encrypted tunnel (via SSH) to the
        machines listed here.  Since this is a two-way (peer to peer)
        connection, it is not necessary to set this option on both
        endpoints.  NixOps will set up <filename>/etc/hosts</filename>
        so that the host names of the machines listed here resolve to
        the IP addresses of the tunnels.  It will also add the alias
        <literal><replaceable>machine</replaceable>-encrypted</literal>
        for each machine.
      '';
    };

  };

}
