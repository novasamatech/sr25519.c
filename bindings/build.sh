#!/bin/bash

set -e

lib_name="sr25519c"
output_dir="./xcframework"
release_dir="./target"

# Clear and recreate output
rm -rf $output_dir
mkdir -p $output_dir

# Build for Apple targets
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim
cargo build --release --target aarch64-apple-darwin

# Create header structure
headers_root="./headers-tmp"
headers_nested="$headers_root/$lib_name"
rm -rf "$headers_root"
mkdir -p "$headers_nested"

# Copy actual header
cp "./generated/sr25519/sr25519.h" "$headers_nested/"

# Create module.modulemap that references the subfolder
cat <<EOF > "$headers_nested/module.modulemap"
module $lib_name {
    header "$lib_name/sr25519.h"
    export *
}
EOF

# Symlink sr25519.h at top-level (so xcodebuild accepts it)
ln -s "$lib_name/sr25519.h" "$headers_root/sr25519.h"

# Build XCFramework using xcodebuild
xcodebuild -create-xcframework \
    -library "$release_dir/aarch64-apple-ios/release/lib${lib_name}.a" \
    -headers "$headers_root" \
    -library "$release_dir/aarch64-apple-ios-sim/release/lib${lib_name}.a" \
    -headers "$headers_root" \
    -library "$release_dir/aarch64-apple-darwin/release/lib${lib_name}.a" \
    -headers "$headers_root" \
    -output "$output_dir/${lib_name}.xcframework"

# Cleanup
rm -rf "$headers_root"

echo "✅ XCFramework created at $output_dir/${lib_name}.xcframework"
