#!/usr/bin/env python3
"""
Fetch legitimate package lists from HuggingFace datasets for hallucination detection.

Usage:
    python fetch-packages.py

Or with huggingface_hub:
    pip install huggingface_hub pandas pyarrow
    python fetch-packages.py
"""

import os
import sys

PACKAGES_DIR = os.path.join(os.path.dirname(__file__), '..', 'packages')
os.makedirs(PACKAGES_DIR, exist_ok=True)

DATASETS = {
    'dart': 'dchitimalla1/dart-20250529',
    'perl': 'dchitimalla1/perl-20250529',
    'raku': 'dchitimalla1/raku-20250523',
}

def fetch_with_datasets_library():
    """Fetch using the datasets library (recommended)."""
    try:
        from datasets import load_dataset

        for ecosystem, dataset_name in DATASETS.items():
            print(f"Fetching {ecosystem} packages from {dataset_name}...")
            try:
                dataset = load_dataset(dataset_name, split='train')

                # Handle different column names (name or text)
                if 'name' in dataset.column_names:
                    packages = dataset['name']
                elif 'text' in dataset.column_names:
                    packages = dataset['text']
                else:
                    packages = dataset[dataset.column_names[0]]

                output_file = os.path.join(PACKAGES_DIR, f'{ecosystem}.txt')
                with open(output_file, 'w') as f:
                    f.write('\n'.join(str(p) for p in packages if p))

                print(f"  Saved {len(packages)} packages to {output_file}")
            except Exception as e:
                print(f"  Error fetching {ecosystem}: {e}")

        return True
    except ImportError:
        return False

def fetch_with_huggingface_hub():
    """Fetch using huggingface_hub and pandas."""
    try:
        from huggingface_hub import hf_hub_download
        import pandas as pd

        for ecosystem, dataset_name in DATASETS.items():
            print(f"Fetching {ecosystem} packages from {dataset_name}...")
            try:
                # Download the parquet file
                parquet_path = hf_hub_download(
                    repo_id=dataset_name,
                    filename="data/train-00000-of-00001.parquet",
                    repo_type="dataset"
                )

                # Read parquet and extract names
                df = pd.read_parquet(parquet_path)
                packages = df['name'].tolist()

                output_file = os.path.join(PACKAGES_DIR, f'{ecosystem}.txt')
                with open(output_file, 'w') as f:
                    f.write('\n'.join(packages))

                print(f"  Saved {len(packages)} packages to {output_file}")
            except Exception as e:
                print(f"  Error fetching {ecosystem}: {e}")

        return True
    except ImportError:
        return False

def fetch_with_requests():
    """Fetch using raw HTTP requests (fallback)."""
    import urllib.request
    import json

    print("Note: Using HTTP fallback. For better results, install: pip install datasets")

    for ecosystem, dataset_name in DATASETS.items():
        print(f"Fetching {ecosystem} packages from {dataset_name}...")
        try:
            # Try to get the dataset info via API
            api_url = f"https://huggingface.co/api/datasets/{dataset_name}"
            with urllib.request.urlopen(api_url) as response:
                info = json.loads(response.read())
                print(f"  Dataset found: {info.get('id', dataset_name)}")
                print(f"  Install 'datasets' library to download: pip install datasets")
        except Exception as e:
            print(f"  Could not fetch {ecosystem}: {e}")

    return False

def main():
    print("=" * 60)
    print("Fetching Package Lists for Hallucination Detection")
    print("=" * 60)
    print()

    # Try different methods in order of preference
    if fetch_with_datasets_library():
        print("\nSuccess! Used 'datasets' library.")
    elif fetch_with_huggingface_hub():
        print("\nSuccess! Used 'huggingface_hub' library.")
    else:
        fetch_with_requests()
        print("\n" + "=" * 60)
        print("To download packages, install required libraries:")
        print("  pip install datasets")
        print("  # or")
        print("  pip install huggingface_hub pandas pyarrow")
        print("=" * 60)
        sys.exit(1)

    print()
    print("Package files saved to:", PACKAGES_DIR)
    print()
    print("Package counts:")
    for ecosystem in DATASETS.keys():
        filepath = os.path.join(PACKAGES_DIR, f'{ecosystem}.txt')
        if os.path.exists(filepath):
            with open(filepath) as f:
                count = sum(1 for _ in f)
            print(f"  {ecosystem}: {count:,} packages")

if __name__ == '__main__':
    main()
