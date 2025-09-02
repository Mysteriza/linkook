# linkook/scanner/site_scanner.py

import re
import logging
import requests
from linkook.provider.provider import Provider
from typing import Set, Dict, Any, Optional, Tuple, List


class SiteScanner:
    def __init__(self, timeout: int = 10, proxy: Optional[str] = None):
        self.timeout = timeout
        self.proxy = proxy
        self.all_providers = {}
        self.to_scan = {}
        self.visited_urls = set()
        self.found_accounts = {}
        self.found_usernames = set()
        self.found_emails = set()
        self.found_passwords = set()
        self.breach_count = set()
        self.check_breach = False
        self.hibp_key = None

        self.email_regex = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

    def _extract_data(self, pattern: str, text: str) -> Optional[str]:
        if not pattern:
            return None
        match = re.search(pattern, text, re.DOTALL)
        if match:
            # Mengambil grup pertama dan membersihkan spasi berlebih
            return ' '.join(match.group(1).strip().split())
        return None

    def deep_scan(self, user: str, current_provider: Provider) -> dict:

        result: Dict[str, Any] = {
            "found": False,
            "profile_url": "",
            "other_links": {},
            "other_usernames": set(),
            "infos": {},
            "error": None,
            "extracted_data": {} # Untuk menyimpan data baru
        }

        provider = current_provider

        profile_url = provider.build_url(user)

        if profile_url in self.visited_urls:
            logging.debug(f"URL {profile_url} already visited")
            return result
        self.visited_urls.add(profile_url)

        result["profile_url"] = profile_url

        status_code, html_content = self.fetch_user_profile(user, provider)
        check_res = self.check_availability(status_code, html_content, provider)

        result["found"] = check_res["found"]
        result["error"] = check_res["error"]

        if result["error"]:
            return result

        if not check_res["found"]:
            return result
        
        # Ekstraksi data baru jika pola ada
        if hasattr(provider, "extract_patterns") and provider.extract_patterns:
            for key, pattern in provider.extract_patterns.items():
                extracted_value = self._extract_data(pattern, html_content)
                if extracted_value:
                    result["extracted_data"][key] = extracted_value

        search_res = self.search_in_response(html_content, provider)

        result["other_links"] = search_res["other_links"]
        result["other_usernames"] = search_res["other_usernames"]
        result["infos"] = search_res["infos"]

        self.found_usernames.update(result["other_usernames"])
        if result["infos"]["emails"]:
            found_email_tuple = tuple(sorted(result["infos"]["emails"].items()))
            self.found_emails.update(found_email_tuple)

        if result["infos"]["passwords"]:
            found_pass_tuple = tuple((key, tuple(value)) for key, value in result["infos"]["passwords"].items())
            self.found_passwords.update(found_pass_tuple)

        if result["infos"]["breach_count"]:
            breach_count_tuple = tuple((key, value) for key, value in result["infos"]["breach_count"].items())
            self.breach_count.update(breach_count_tuple)

        if provider.name not in self.found_accounts:
            self.found_accounts[provider.name] = set()
        self.found_accounts[provider.name].add(profile_url)

        for pname, urls in result["other_links"].items():
            provider = self.all_providers.get(pname)
            if pname not in self.found_accounts:
                self.found_accounts[pname] = set()
            
            url_list = urls if isinstance(urls, list) else [urls]
            for url in url_list:
                extracted_users = provider.extract_user(url)
                if not extracted_users:
                    continue
                username = extracted_users.pop()
                final_url = provider.build_url(username)
                self.found_accounts[pname].add(final_url)

        return result

    def check_availability(self, status_code: int, html_content: str, current_provider: Provider) -> dict:
        result: Dict[str, Any] = { "found": False, "error": None }
        provider = current_provider

        if status_code is None:
            result["error"] = "Failed to retrieve profile page (network error/timeout)."
            logging.error(f"Network error while fetching URL for {provider.name}")
            return result

        if not (200 <= status_code < 400):
            result["found"] = False
            logging.info(f"Profile not found for {provider.name} based on status code: {status_code}")
            return result

        keyword_conf = getattr(provider, "keyword", None)
        if keyword_conf is None:
            result["found"] = True # Jika tidak ada keyword, anggap ditemukan berdasarkan status code
            logging.warning(f"No keyword config for {provider.name}, assuming found.")
            return result

        not_match_list = keyword_conf.get("notMatch", [])
        if not_match_list and any(bad_kw in html_content for bad_kw in not_match_list):
            result["found"] = False
            logging.info(f"User not found on {provider.name} based on notMatch keywords.")
            return result

        match_list = keyword_conf.get("Match", [])
        if match_list and any(good_kw in html_content for good_kw in match_list):
            result["found"] = True
            logging.info(f"User found on {provider.name} based on Match keywords.")
            return result
        
        # Jika hanya ada notMatch dan tidak ada yang cocok, berarti ditemukan
        if not_match_list and not match_list:
            result["found"] = True
            return result

        result["found"] = False
        return result

    def fetch_user_profile(
        self, user: str, current_provider: Provider
    ) -> Tuple[Optional[int], Optional[str]]:
        provider = current_provider
        method = provider.request_method or "GET"
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
        }
        if provider.headers:
            headers.update(provider.headers)

        payload = provider.build_payload(user) or {}

        if provider.query_url:
            url = provider.build_url(user, provider.query_url)
        else:
            url = provider.build_url(user)

        try:
            session = requests.Session()
            if self.proxy:
                session.proxies = { "http": self.proxy, "https": self.proxy }
            
            resp = session.request(method, url, json=payload if method.upper() == "POST" else None, headers=headers, timeout=self.timeout, allow_redirects=True)
            
            logging.info(f"Response status code for {url}: {resp.status_code}")
            return resp.status_code, resp.text
        except Exception as e:
            logging.error(f"Failed to fetch profile page for URL {url}: {e}")
            return None, None

    def search_in_response(self, html: str, current_provider: Provider) -> dict:
        result: Dict[str, Any] = {
            "other_links": {},
            "other_usernames": set(),
            "infos": {
                "emails": {},
                "passwords": {},
                "breach_count": {},
            },
        }
        provider = current_provider

        if not provider.is_connected and not provider.has_email:
            return result

        if provider.has_email:
            emails_set = self.search_info(html)["emails"]
            for email in emails_set:
                if email in self.found_emails:
                    result["infos"]["emails"][email] = self.found_emails[email]
                else:
                    if self.check_breach:
                        if self.hibp_key is not None:
                            check_res = self.check_HaveIBeenPwned(email)
                            result["infos"]["emails"][email] = check_res[0]
                            result["infos"]["breach_count"][email] = check_res[1]
                        else:
                            result["infos"]["emails"][email] = self.check_HudsonRock(email)
                        if result["infos"]["emails"][email]:
                            check_pass = self.check_ProxyNova(email)
                            if check_pass:
                                result["infos"]["passwords"][email] = check_pass
                    else:
                        result["infos"]["emails"][email] = False
        
        if not provider.is_connected:
            return result

        if provider.handle_regex:
            for prov_name, pattern in provider.handle_regex.items():
                handle = self._extract_data(pattern, html)
                if handle:
                    match_provider = self.all_providers.get(prov_name)
                    if not match_provider:
                        continue
                    if not match_provider.is_userid:
                        result["other_usernames"].add(handle)
                    links = match_provider.build_url(handle)
                    result["other_links"][prov_name] = [links]
            return result

        provs_to_search = [p for name, p in self.all_providers.items() if name != provider.name]

        result["other_links"] = self.search_new_links(html, provs_to_search)
        result["other_usernames"].update(self.search_new_usernames(html, provs_to_search))
        
        return result

    def search_new_links(
        self, html: str, provider_list: List[Provider]
    ) -> Dict[str, List[str]]:
        discovered = {}
        for prov in provider_list:
            matches = prov.extract_links(html)
            if matches:
                discovered[prov.name] = matches
        return discovered

    def search_new_usernames(
        self, html: str, provider_list: List[Provider]
    ) -> Set[str]:
        discovered = set()
        for prov in provider_list:
            if prov.is_userid:
                continue
            matches = prov.extract_user(html)
            if matches:
                discovered.update(matches)
        return discovered

    def search_info(self, html: str) -> Dict[str, Any]:
        result = {"emails": set()}
        matches = re.findall(self.email_regex, html)
        if matches:
            result["emails"].update(matches)
        return result

    def check_HaveIBeenPwned(self, email: str) -> Tuple[bool, int]:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": self.hibp_key,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
        }
        try:
            res = requests.get(url, headers=headers, timeout=5)
            if res.status_code == 200:
                return True, len(res.json())
            return False, 0
        except requests.exceptions.RequestException:
            return False, 0

    def check_HudsonRock(self, email: str) -> bool:
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}"
        try:
            res = requests.get(url, timeout=5)
            if res.status_code == 200 and "is associated with a computer that was infected" in res.json().get("message", ""):
                return True
        except requests.exceptions.RequestException:
            return False
        return False

    def check_ProxyNova(self, email: str) -> Optional[List[str]]:
        url = f"https://api.proxynova.com/comb?query={email}"
        try:
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                lines = res.json().get("lines", [])
                password_set = set()
                prefix = f"{email}:"
                for line in lines:
                    if line.startswith(prefix):
                        parts = line.split(":", 1)
                        if len(parts) == 2 and parts[1].strip():
                            password_set.add(parts[1].strip())
                if password_set:
                    return list(password_set)
        except requests.exceptions.RequestException:
            return None
        return None