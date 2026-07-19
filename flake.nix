{
  description = "sframe-rs: dev shell with the wasm/trunk toolchain for the examples";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      fenix,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ fenix.overlays.default ];
        };

        # Stable rust + the wasm32 target in a single sysroot
        rustToolchain = pkgs.fenix.combine [
          pkgs.fenix.stable.completeToolchain
          pkgs.fenix.targets.wasm32-unknown-unknown.stable.rust-std
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            rustToolchain
            pkgs.trunk
            pkgs.wasm-pack
            # ring's C fallback is cross-compiled to wasm below; clang can target
            # wasm, gcc can't. Unwrapped so the nix wrapper doesn't inject host flags.
            pkgs.llvmPackages.clang-unwrapped
          ];

          CC_wasm32_unknown_unknown = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
        };
      }
    );
}
