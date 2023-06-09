with import <nixpkgs> { };
let
  pythonEnv = python3.withPackages (ps: [
      ps.pandas
      ps.pexpect
      ps.matplotlib
      ps.pyopenssl
    ]);
  fenix = callPackage
    (fetchFromGitHub {
      owner = "nix-community";
      repo = "fenix";
      # commit from: 2023-03-03
      rev = "e2ea04982b892263c4d939f1cc3bf60a9c4deaa1";
      hash = "sha256-AsOim1A8KKtMWIxG+lXh5Q4P2bhOZjoUhFWJ1EuZNNk=";
    })
    { };
  libraries = [ zlib glib ];
in
mkShell {
  buildInputs = libraries;
  nativeBuildInputs = [
    pkg-config
    vim
    openssl
    git
  
    #for the snpguest -- rust nightly is required
    # cargo
    # rustup
    # Note: to use stable, just replace `default` with `stable`
    fenix.default.toolchain
  ];

  # make install strips valueable libraries from our rpath
  LD_LIBRARY_PATH = lib.makeLibraryPath libraries;
  shellHook = ''
    export PATH=${pythonEnv}/bin:$PATH
  '';

  # Set Environment Variables
  RUST_BACKTRACE = 1;
}

