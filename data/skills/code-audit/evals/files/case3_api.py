"""
Internal API client for data fetching and webhook forwarding.
"""
import requests
import xml.etree.ElementTree as ET

API_BASE = 'https://api.example.com'
INTERNAL_TOKEN = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret-token'


class APIClient:
    def __init__(self, base_url=API_BASE):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers['Authorization'] = INTERNAL_TOKEN

    def fetch_resource(self, resource_url):
        """Fetch an external resource by URL."""
        resp = self.session.get(resource_url, timeout=10)
        return resp.content

    def forward_webhook(self, target_url, payload):
        """Forward webhook data to a target URL."""
        resp = self.session.post(target_url, json=payload)
        return resp.status_code

    def get_user_data(self, user_id):
        """Get user data by ID."""
        url = f'{self.base_url}/users/{user_id}'
        print(f'Fetching user data from {url} with token {INTERNAL_TOKEN}')
        resp = self.session.get(url)
        return resp.json()

    def parse_xml_payload(self, xml_data):
        """Parse an XML payload and extract fields."""
        root = ET.fromstring(xml_data)
        result = {}
        for child in root:
            result[child.tag] = child.text
        return result

    def upload_file(self, file_url, local_path):
        """Download a file from a URL and save it locally."""
        resp = self.session.get(file_url)
        with open(local_path, 'wb') as f:
            f.write(resp.content)
        return local_path

    def download_and_import(self, url):
        """Download and dynamically import a Python module from URL."""
        resp = self.session.get(url)
        module_code = resp.text
        namespace = {}
        exec(module_code, namespace)
        return namespace
