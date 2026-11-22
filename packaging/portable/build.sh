#!/usr/bin/env bash
# Build on Debian 12 to establish the minimum glibc ABI.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo "Usage: $0 /path/to/runtime-ARCH OUTPUT_DIRECTORY" >&2
    exit 2
fi
src=$(cd "$(dirname "$0")/../.." && pwd)
runtime=$(realpath "$1")
arch=$(uname -m)
case $arch in
    x86_64) digest=617aa77314d57c8b8e4fae9c3f0b35af7b30d5529cb69e98f64f92510ed98a46 ;;
    aarch64) digest=9a72a744d221576c9347ec074243acc5c3c7568896b12714e0e82e9f0bf47900 ;;
    *) echo "Unsupported architecture: $arch" >&2; exit 2 ;;
esac
echo "$digest  $runtime" | sha256sum -c -
mkdir -p "$2"
out=$(realpath "$2")
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
prefix=/opt/vpnctl/current
stage=$work/stage
# Build the same pinned TUI as the flake, including on Debian 12.
curl -fsSL --retry 3 -o "$work/ftxui.tar.gz" https://codeload.github.com/ArthurSonzogni/FTXUI/tar.gz/refs/tags/v7.0.3
echo "e7c62ffe19009759821b4f0f8df7f2a6fb83784c3a9f1477d81f56d3ee723c88  $work/ftxui.tar.gz" | sha256sum -c -
tar -xf "$work/ftxui.tar.gz" -C "$work"
cmake -S "$work/FTXUI-7.0.3" -B "$work/ftxui-build" -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX="$work/deps"
cmake --build "$work/ftxui-build" --parallel "${BUILD_JOBS:-2}"
cmake --install "$work/ftxui-build"
cmake -S "$src" -B "$work/build" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$work/deps" -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib -DVPNCTL_NATIVE_SYSTEMD=ON -DVPNCTL_PORTABLE=ON
cmake --build "$work/build" --parallel "${BUILD_JOBS:-2}"
ctest --test-dir "$work/build" --output-on-failure
DESTDIR="$stage" cmake --install "$work/build" --strip
version=$(sed -n 's/^CMAKE_PROJECT_VERSION:STATIC=//p' "$work/build/CMakeCache.txt")
name=vpnctl-${version:?}-$arch
bundle=$work/$name
mv "$stage$prefix" "$bundle"
cd "$bundle"
install -Dm644 "$work/FTXUI-7.0.3/LICENSE" share/licenses/ftxui/LICENSE
install -d lib/vpnctl
for binary in bin/vpnctl bin/vpnctl-daemon; do
    libs=$(ldd "$binary")
    if [[ $libs == *'not found'* ]]; then echo "$libs" >&2; exit 1; fi
    while read -r soname path; do
        case "$soname" in
            libc.so.*|libm.so.*|libpthread.so.*|libdl.so.*|librt.so.*) continue ;;
        esac
        install -m 0644 "$path" "lib/vpnctl/$soname"
        owner=$(dpkg-query -S "*/$(basename "$(realpath "$path")")" | head -n1 | cut -d: -f1)
        install -Dm644 "/usr/share/doc/$owner/copyright" "share/licenses/$owner/copyright"
    done < <(awk '$2 == "=>" && $3 ~ /^\// {print $1, $3}' <<<"$libs")
    patchelf --set-rpath '$ORIGIN/../lib/vpnctl' "$binary"
done
for library in lib/vpnctl/*.so*; do
    patchelf --set-rpath '$ORIGIN' "$library"
done
cp -Lr /usr/share/common-licenses share/licenses/
install -m 0755 "$src/packaging/portable/"{AppRun,install-backend} .
install -m 0644 "$src/packaging/portable/"{vpnctl.desktop,vpnctl.svg} .
install -m 0644 "$src/docs/linux.md" README.md
ln -s bin/vpnctl vpnctl
ln -s vpnctl.svg .DirIcon
epoch=${SOURCE_DATE_EPOCH:-0}
tar -C "$work" --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    -cf - "$name" | gzip -n > "$work/$name.tar.gz"
env -u SOURCE_DATE_EPOCH mksquashfs "$bundle" "$work/bundle.sqfs" -noappend -all-root -no-xattrs \
    -comp gzip -all-time "$epoch" -mkfs-time "$epoch" -processors "${BUILD_JOBS:-2}" -quiet
cat "$runtime" "$work/bundle.sqfs" > "$work/$name.AppImage"
chmod 0755 "$work/$name.AppImage"
"$work/$name.AppImage" --appimage-extract-and-run --help
mv "$work/$name.AppImage" "$work/$name.tar.gz" "$out/"
