#!/bin/bash
# Fetch legitimate package lists from HuggingFace datasets for hallucination detection

set -e

PACKAGES_DIR="$(dirname "$0")/../packages"
mkdir -p "$PACKAGES_DIR"

echo "Fetching package lists from HuggingFace..."

# Dart packages
echo "Fetching Dart packages from dchitimalla1/dart-20250529..."
curl -sL "https://huggingface.co/datasets/dchitimalla1/dart-20250529/resolve/main/packages.txt" -o "$PACKAGES_DIR/dart.txt" || \
curl -sL "https://huggingface.co/datasets/dchitimalla1/dart-20250529/raw/main/packages.txt" -o "$PACKAGES_DIR/dart.txt"

# Perl packages
echo "Fetching Perl packages from dchitimalla1/perl-20250530..."
curl -sL "https://huggingface.co/datasets/dchitimalla1/perl-20250530/resolve/main/packages.txt" -o "$PACKAGES_DIR/perl.txt" || \
curl -sL "https://huggingface.co/datasets/dchitimalla1/perl-20250530/raw/main/packages.txt" -o "$PACKAGES_DIR/perl.txt"

# Raku packages
echo "Fetching Raku packages from dchitimalla1/raku-20250523..."
curl -sL "https://huggingface.co/datasets/dchitimalla1/raku-20250523/resolve/main/packages.txt" -o "$PACKAGES_DIR/raku.txt" || \
curl -sL "https://huggingface.co/datasets/dchitimalla1/raku-20250523/raw/main/packages.txt" -o "$PACKAGES_DIR/raku.txt"

echo ""
echo "Done! Package lists saved to $PACKAGES_DIR"
echo ""
ls -lh "$PACKAGES_DIR"/*.txt 2>/dev/null || echo "Note: Some files may need manual download"
echo ""
echo "Package counts:"
for f in "$PACKAGES_DIR"/*.txt; do
  if [ -f "$f" ]; then
    count=$(wc -l < "$f" | tr -d ' ')
    echo "  $(basename "$f"): $count packages"
  fi
done
