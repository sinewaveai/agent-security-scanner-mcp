#!/usr/bin/env python3
"""
Fetch package lists from garak-llm Hugging Face datasets for hallucination detection.

Datasets:
- garak-llm/pypi-20241031 (Python)
- garak-llm/npm-20241031 (JavaScript)
- garak-llm/rubygems-20241031 (Ruby)
- garak-llm/crates-20250307 (Rust)
- garak-llm/raku-20250811 (Raku)
- garak-llm/perl-20250811 (Perl)
- garak-llm/dart-20250811 (Dart)
"""

import os
import sys

try:
    from datasets import load_dataset
except ImportError:
    print("Error: 'datasets' library not installed.")
    print("Install with: pip install datasets")
    sys.exit(1)

# Dataset configurations
DATASETS = {
    'pypi': {
        'name': 'garak-llm/pypi-20241031',
        'output': 'pypi.txt',
        'description': 'Python packages from PyPI + stdlib'
    },
    'npm': {
        'name': 'garak-llm/npm-20241031',
        'output': 'npm.txt',
        'description': 'JavaScript packages from npm registry'
    },
    'rubygems': {
        'name': 'garak-llm/rubygems-20241031',
        'output': 'rubygems.txt',
        'description': 'Ruby gems from RubyGems'
    },
    'crates': {
        'name': 'garak-llm/crates-20250307',
        'output': 'crates.txt',
        'description': 'Rust crates from crates.io + stdlib'
    },
    'raku': {
        'name': 'garak-llm/raku-20250811',
        'output': 'raku.txt',
        'description': 'Raku modules from raku.land'
    },
    'perl': {
        'name': 'garak-llm/perl-20250811',
        'output': 'perl.txt',
        'description': 'Perl modules from MetaCPAN'
    },
    'dart': {
        'name': 'garak-llm/dart-20250811',
        'output': 'dart.txt',
        'description': 'Dart packages from pub.dev'
    }
}

def get_package_column(dataset):
    """Determine the column name containing package names."""
    columns = dataset.column_names
    # Try common column names
    for col in ['name', 'package', 'package_name', 'text', 'module']:
        if col in columns:
            return col
    # Return first column as fallback
    return columns[0] if columns else None

def fetch_dataset(key, config, output_dir):
    """Fetch a single dataset and save package names."""
    print(f"\n{'='*60}")
    print(f"Fetching: {config['name']}")
    print(f"Description: {config['description']}")
    print('='*60)

    try:
        # Load the dataset
        dataset = load_dataset(config['name'], split='train')

        # Find the package name column
        col = get_package_column(dataset)
        if not col:
            print(f"  ERROR: Could not find package column in {config['name']}")
            return 0

        print(f"  Using column: '{col}'")
        print(f"  Total rows: {len(dataset):,}")

        # Extract unique package names
        packages = set()
        for row in dataset:
            pkg = row[col]
            if pkg and isinstance(pkg, str) and pkg.strip():
                packages.add(pkg.strip())

        print(f"  Unique packages: {len(packages):,}")

        # Write to file
        output_path = os.path.join(output_dir, config['output'])
        with open(output_path, 'w', encoding='utf-8') as f:
            for pkg in sorted(packages):
                f.write(pkg + '\n')

        # Get file size
        size_kb = os.path.getsize(output_path) / 1024
        print(f"  Saved to: {config['output']} ({size_kb:.1f} KB)")

        return len(packages)

    except Exception as e:
        print(f"  ERROR: {e}")
        return 0

def main():
    # Determine output directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, '..', 'packages')
    os.makedirs(output_dir, exist_ok=True)

    print("Package List Fetcher for Hallucination Detection")
    print(f"Output directory: {output_dir}")

    # Fetch each dataset
    totals = {}
    for key, config in DATASETS.items():
        count = fetch_dataset(key, config, output_dir)
        totals[key] = count

    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    total = 0
    for key, count in totals.items():
        print(f"  {DATASETS[key]['output']:20} {count:>10,} packages")
        total += count
    print("-"*60)
    print(f"  {'TOTAL':20} {total:>10,} packages")
    print("="*60)

if __name__ == '__main__':
    main()
