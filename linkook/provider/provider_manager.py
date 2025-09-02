# provider_manager.py

import os
import json
import logging
import requests
from typing import Dict
from colorama import Fore, Style
from importlib.resources import files
from linkook.provider.provider import Provider
from requests.exceptions import RequestException


class ProviderManager:
    def __init__(
        self,
        remote_json_url: str = "https://raw.githubusercontent.com/JackJuly/linkook/refs/heads/main/linkook/provider/provider.json",
        local_json_path: str = "linkook/provider/provider.json",
        force_local: bool = False,
        timeout: int = 10,
    ):
        self.remote_json_url = remote_json_url
        self.local_json_path = local_json_path
        self.force_local = force_local
        self.timeout = timeout

        if local_json_path is None:
            self.local_json_path = files("linkook.provider").joinpath("provider.json")

        self._providers: Dict[str, Provider] = {}

    def load_providers(self) -> Dict[str, Provider]:
        if self.force_local:
            data = self._load_local_json(self.local_json_path)
        else:
            try:
                data = self._load_remote_json(self.remote_json_url, self.timeout)
            except (RequestException, ValueError) as e:
                print(
                    f"{Fore.YELLOW}Remote loading failed! Falling back to local provider.json...{Style.RESET_ALL}"
                )
                logging.warning(f"Remote loading failed: {e}")
                data = self._load_local_json(self.local_json_path)

        self._providers = {}
        for provider_name, provider_conf in data.items():
            provider_obj = Provider.from_dict(provider_name, provider_conf)
            self._providers[provider_name] = provider_obj

        return self._providers

    def _load_remote_json(self, url: str, timeout: int) -> dict:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        return data

    def _load_local_json(self, path: str) -> dict:
        if not os.path.isfile(path):
            if path != "linkook/provider/provider.json":
                print(f"{Fore.RED}Local provider.json not found at: {path}{Style.RESET_ALL}")
                raise FileNotFoundError
            else:
                path = files("linkook.provider").joinpath("provider.json")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data

    def get_all_providers(self) -> Dict[str, Provider]:
        return self._providers

    def get_provider(self, provider_name: str) -> Provider:
        return self._providers.get(provider_name)

    def filter_providers(
        self, have_profile_url: bool = True, is_connected: bool = True
    ) -> Dict[str, Provider]:
        filtered = {}
        for name, p in self._providers.items():
            if not p.keyword:
                continue
            if p.is_userid:
                continue
            if have_profile_url and not p.profile_url:
                continue
            if is_connected and not p.is_connected:
                continue
            filtered[name] = p

        return filtered