{
  description = "Python3.13 development environment";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      systems = nixpkgs.lib.systems.flakeExposed;
      forEachSystem =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs { inherit system; };
          }
        );
    in
    {
      devShells = forEachSystem (
        { pkgs, ... }:
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              uv
            ];
            shellHook = ''
              if [ ! -d "$UV_PROJECT_ENVIRONMENT" ]; then
                uv venv "$UV_PROJECT_ENVIRONMENT" --python "$UV_PYTHON"
              fi

              source "$UV_PROJECT_ENVIRONMENT/bin/activate"
            '';
            env = {
              UV_PROJECT_ENVIRONMENT = ".venv";
              UV_PYTHON = "${pkgs.python313}/bin/python3";
              UV_NO_SYNC = "1";
              UV_PYTHON_DOWNLOADS = "never";
            };
          };
        }
      );
    };
}
