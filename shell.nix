{ pkgs ? import <nixpkgs> { } }:
with pkgs;
stdenvNoCC.mkDerivation {
  name = "dev-shell";
  buildInputs = [ cargo-edit rustup llvmPackages_latest.clang ];
}
