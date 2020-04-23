{ pkgs ? import <nixpkgs> {

  overlays = [
    (import ../../nix-community/poetry2nix/overlay.nix)
  ];

} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.poetry
    pkgs.python3
    pkgs.openssl
  ];

  SOURCE_DATE_EPOCH = "315532800";
}
