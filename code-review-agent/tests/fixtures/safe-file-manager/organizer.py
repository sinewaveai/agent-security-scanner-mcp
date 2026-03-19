"""File organizer - sorts files into categorized directories."""

import os
import sys
import shutil
import logging

logging.basicConfig(filename='organizer.log', level=logging.INFO)
logger = logging.getLogger(__name__)

CATEGORIES = {
    'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg'],
    'docs': ['.pdf', '.doc', '.docx', '.txt', '.md', '.csv'],
    'code': ['.py', '.js', '.ts', '.java', '.go', '.rs'],
    'archives': ['.zip', '.tar', '.gz', '.rar', '.7z'],
    'media': ['.mp3', '.mp4', '.avi', '.mkv', '.wav'],
}


def get_category(filename):
    ext = os.path.splitext(filename)[1].lower()
    for category, extensions in CATEGORIES.items():
        if ext in extensions:
            return category
    return 'other'


def organize(directory, dry_run=False):
    if not os.path.isdir(directory):
        logger.error(f"Not a directory: {directory}")
        return

    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if not os.path.isfile(filepath):
            continue

        category = get_category(filename)
        target_dir = os.path.join(directory, category)

        if not dry_run:
            os.makedirs(target_dir, exist_ok=True)
            target_path = os.path.join(target_dir, filename)

            # Handle duplicates
            counter = 1
            base, ext = os.path.splitext(filename)
            while os.path.exists(target_path):
                target_path = os.path.join(target_dir, f"{base}_{counter}{ext}")
                counter += 1

            shutil.move(filepath, target_path)
            logger.info(f"Moved {filename} -> {category}/")
        else:
            logger.info(f"[DRY RUN] Would move {filename} -> {category}/")


def cleanup_empty_dirs(directory):
    for dirpath, dirnames, filenames in os.walk(directory, topdown=False):
        if not filenames and not dirnames:
            os.rmdir(dirpath)
            logger.info(f"Removed empty directory: {dirpath}")


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    dry_run = '--dry-run' in sys.argv
    organize(target, dry_run)
    if not dry_run:
        cleanup_empty_dirs(target)
