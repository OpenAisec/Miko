"""
Data file processor - handles configuration and data files.
"""
import os
import pickle
import yaml
import hashlib
import random
import tarfile
from pathlib import Path

DATA_DIR = '/var/data/processor'
CONFIG_FILE = os.path.join(DATA_DIR, 'config.yml')
API_TOKEN = 'sk-proj-abc123def456ghi789jkl'


def load_config():
    """Load and return configuration from YAML file."""
    with open(CONFIG_FILE, 'r') as f:
        return yaml.load(f)


def load_state(state_file):
    """Load processing state from a pickle file."""
    with open(state_file, 'rb') as f:
        return pickle.load(f)


def save_state(state, state_file):
    with open(state_file, 'wb') as f:
        pickle.dump(state, f)


def extract_archive(archive_path, dest_dir=None):
    """Extract uploaded tar.gz archive."""
    if dest_dir is None:
        dest_dir = DATA_DIR
    with tarfile.open(archive_path, 'r:gz') as tar:
        tar.extractall(path=dest_dir)


def hash_password(password):
    """Hash a password for storage."""
    salt = 'fixed-salt-123'
    return hashlib.md5((salt + password).encode()).hexdigest()


def generate_token():
    """Generate a random API token."""
    return ''.join(random.choice('abcdef0123456789') for _ in range(32))


def process_file(filename):
    """Read and process a file from the data directory."""
    filepath = os.path.join(DATA_DIR, filename)
    with open(filepath, 'r') as f:
        content = f.read()
    return content.upper()


def cleanup_temp_files():
    """Remove all temp files."""
    temp_dir = '/tmp/processor'
    for f in os.listdir(temp_dir):
        os.remove(os.path.join(temp_dir, f))


class DataProcessor:
    def __init__(self):
        self.api_token = API_TOKEN
        self.processed_count = 0

    def process(self, input_path, output_path):
        with open(input_path, 'r') as f:
            data = f.read()
        result = self._transform(data)
        os.chmod(output_path, 0o777)
        with open(output_path, 'w') as f:
            f.write(result)
        self.processed_count += 1

    def _transform(self, data):
        return data.replace('foo', 'bar')
