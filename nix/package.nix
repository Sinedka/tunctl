{
  lib,
  stdenv,
  cmake,
  openssl,
  nlohmann_json,
  ncurses,
  python3,
  makeWrapper,
  iproute2,
  iputils,
  getent,
  curl,
  dnsutils,
  systemd,
  nftables,
}:
stdenv.mkDerivation {
  pname = "vpnctl";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../CMakeLists.txt
      ../src
      ../include
      ../tests
    ];
  };
  nativeBuildInputs = [
    cmake
    makeWrapper
    openssl
  ];
  buildInputs = [
    openssl
    nlohmann_json
    ncurses
    python3
  ];
  cmakeFlags = [ "-DVPNCTL_NATIVE_SYSTEMD=OFF" ];
  doCheck = true;
  postFixup = ''
    substituteInPlace $out/libexec/vpnctl-dns $out/libexec/vpnctl-prepare --replace-fail "#!${python3}/bin/python3" "#!${
      python3.withPackages (p: [ p.dnspython ])
    }/bin/python3"
    wrapProgram $out/bin/vpnctl --prefix PATH : ${
      lib.makeBinPath [
        iproute2
        iputils
        getent
        curl
        dnsutils
        systemd
      ]
    }:$out/libexec:$out/bin
    wrapProgram $out/bin/vpnctl-daemon --set PATH ${
      lib.makeBinPath [
        systemd
        iproute2
        nftables
      ]
    }
  '';
  meta.mainProgram = "vpnctl";
}
