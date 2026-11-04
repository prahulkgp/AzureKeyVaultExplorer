{
  description = "Azure Key Vault Explorer dev shell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      devShells = forAll (pkgs:
        let
          dotnet = pkgs.dotnetCorePackages.sdk_10_0;
          hp = pkgs.stdenv.hostPlatform;
          rid =
            if hp.isDarwin then (if hp.isAarch64 then "osx-arm64" else "osx-x64")
            else (if hp.isAarch64 then "linux-arm64" else "linux-x64");

          build-mac = pkgs.writeShellScriptBin "build-mac" ''
            set -euo pipefail
            root="$(git rev-parse --show-toplevel)"
            cd "$root/src/uno/AzureKeyVaultStudio"
            dotnet publish -f net10.0-desktop \
              -p:UnoMacOSCustomInfoPlist=Info.plist -p:PackageFormat=app \
              -p:SelfContained=true -p:PublishReadyToRun=true \
              -r ${rid} -c Release ./AzureKeyVaultStudio.csproj "$@"
            ls -d "$PWD"/bin/Release/net10.0-desktop/${rid}/publish/*.app
          '';

          install-mac = pkgs.writeShellScriptBin "install-mac" ''
            set -euo pipefail
            root="$(git rev-parse --show-toplevel)"
            app="$(ls -d "$root"/src/uno/AzureKeyVaultStudio/bin/Release/net10.0-desktop/${rid}/publish/*.app | head -1)"
            dest="''${1:-$HOME/Applications}"
            mkdir -p "$dest"
            rm -rf "$dest/$(basename "$app")"
            cp -R "$app" "$dest/"
            xattr -cr "$dest/$(basename "$app")"
            echo "Installed: $dest/$(basename "$app")"
          '';
        in {
          default = pkgs.mkShellNoCC {
            packages = [ dotnet build-mac install-mac pkgs.git ];
            shellHook = ''
              export DOTNET_ROOT="${dotnet}/share/dotnet"
              export DOTNET_CLI_HOME="$PWD/.devshell/dotnet-home"
              export NUGET_PACKAGES="$PWD/.devshell/nuget"
              export DOTNET_CLI_TELEMETRY_OPTOUT=1
              export DOTNET_NOLOGO=1
              export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
              mkdir -p "$DOTNET_CLI_HOME" "$NUGET_PACKAGES"
            '';
          };
        });
    };
}
