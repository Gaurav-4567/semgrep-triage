"""Sample module for extractor tests."""

import os
from pathlib import Path
from typing import Optional

import requests
from security_utils import escape_html, validate_url


def helper(x: int) -> int:
    return x + 1


class Service:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def fetch(self, path: str) -> dict:
        url = f"{self.base_url}/{path}"
        if not validate_url(url):
            return {}
        response = requests.get(url, timeout=10)
        return response.json()

    def fetch_with_helper(self, path: str) -> int:
        result = self.fetch(path)
        return helper(result["value"])


def render(value: str) -> str:
    safe = escape_html(value)
    return f"<div>{safe}</div>"


def top_level_function(data):
    eval(data)  # intentional finding for testing
