#!/bin/bash

set -e

lib_name="sr25519"
output_dir="./xcframework"
release_dir="./target"

rm -rf $output_dir
mkdir -p $output_dir

echo "Building .a libraries"

cargo build --release --target aarch64-apple-ios
cargo lipo --release --targets x86_64-apple-ios,aarch64-apple-ios-sim

# We need single folder with headers to put module map within it
headers_temp_dir="./headers-tmp"
mkdir -p $headers_temp_dir
cp "./Generated/sr25519/sr25519.h" $headers_temp_dir

echo "Copied headers to temporary folder: $headers_temp_dir"

# Create module.modulemap file
cat <<EOF >$headers_temp_dir/module.modulemap
module ${lib_name} {
    header "sr25519.h"
    export *
}
EOF

echo "Created module map at: $headers_temp_dir/module.modulemap"

# Here we need 2 lines (-library and -headers) for each architecture
xcodebuild -create-xcframework \
    -library $release_dir/aarch64-apple-ios/release/lib${lib_name}.a \
    -headers $headers_temp_dir \
    -library $release_dir/universal/release/lib${lib_name}.a \
    -headers $headers_temp_dir \
    -output $output_dir/${lib_name}.xcframework

echo "XCFramework created at $output_dir/${lib_name}.xcframework"

rm -rf $headers_temp_dir

echo "Cleanup finished"