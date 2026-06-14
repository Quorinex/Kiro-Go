{
  description = "Development shell for Kiro-Go";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go
          ];

          shellHook = ''
            export GOPATH="$PWD/.go"
            export GOCACHE="$PWD/.cache/go-build"
            export PATH="$GOPATH/bin:$PATH"
          '';
        };
      }
    );
}
