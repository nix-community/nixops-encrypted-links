{ pkgs ? import <nixpkgs> {

  overlays = [
    (import ../../nix-community/poetry2nix/overlay.nix)
  ];

} }:

pkgs.poetry2nix.mkPoetryApplication {
  projectDir = ./.;

  overrides = pkgs.poetry2nix.overrides.withDefaults(self: super: {

    nixops = super.nixops.overrideAttrs(old: {
      buildInputs = old.buildInputs ++ [
        self.poetry
      ];
    });

  });

}
