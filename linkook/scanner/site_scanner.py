# site_scanner.py

import re
import logging
import asyncio
import aiohttp
from aiohttp import ClientTimeout
from fake_useragent import UserAgent
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
        self.ua = UserAgent()

    async def deep_scan(self, user: str, current_provider: Provider, session: aiohttp.ClientSession) -> dict:

        result: Dict[str, Any] = {
            "found": False,
            "profile_url": "",
            "other_links": {},
            "other_usernames": set(),
            "infos": {},
            "error": None,
        }

        provider = current_provider

        profile_url = provider.build_url(user)

        if profile_url in self.visited_urls:
            logging.debug(f"URL {profile_url} already visited")
            return result
        self.visited_urls.add(profile_url)

        result["profile_url"] = profile_url

        status_code, html_content = await self.fetch_user_profile(user, provider, session)
        check_res = self.check_availability(status_code, html_content, provider)

        result["found"] = check_res["found"]
        result["error"] = check_res["error"]

        if result["error"]:
            return result

        if not check_res["found"]:
            return result

        search_res = await self.search_in_response(html_content, provider, session)

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
        return result

    def check_availability(self, status_code: int, html_content: str, current_provider: Provider) -> dict:

        result: Dict[str, Any] = {
            "found": False,
            "error": None,
        }

        provider = current_provider

        if status_code is None:
            result["error"] = (
                "Failed to retrieve the profile page (network error/timeout)."
            )
            result["found"] = False
            logging.error(f"Network error while fetching URL")
            return result

        if status_code != 200:
             result["found"] = False
             logging.info(f"Profile not found based on status code: {status_code}")
             return result

        global_not_match = [
            "404 Not Found",
            "Page Not Found",
            "Page not found",
            "The page you requested was not found",
            "User not found",
            "This page could not be found",
            "This page isn't available",
            "The link you followed may be broken",
            "Sorry, this page isn't available",
            "This content isn't available right now",
            "This account doesn’t exist",
            "This account does not exist",
            "Account suspended",
            "Profile isn't available The link may be broken, or the profile may have been removed."
        ]

        keyword_conf = getattr(provider, "keyword", None)
        if keyword_conf is None:
            if any(bad_kw.lower() in html_content.lower() for bad_kw in global_not_match):
                result["found"] = False
                logging.info(f"User not found based on global notMatch keywords")
                return result
            
            result["found"] = True
            return result

        match_list = keyword_conf.get("Match", [])
        not_match_list = keyword_conf.get("notMatch", [])

        if not_match_list:
            if any(bad_kw in html_content for bad_kw in not_match_list):
                result["found"] = False
                logging.info(
                    f"User not found based on notMatch keywords for provider: {provider.name}"
                )
                return result
            else:
                if not match_list:
                    if any(bad_kw.lower() in html_content.lower() for bad_kw in global_not_match):
                        result["found"] = False
                        logging.info(f"User not found based on global notMatch keywords (override)")
                        return result

                    result["found"] = True
                    logging.info(
                        f"User found based on notMatch keywords for provider: {provider.name}"
                    )
                    return result

        if match_list:
            if any(good_kw in html_content for good_kw in match_list):
                result["found"] = True
                logging.info(
                    f"User found based on Match keywords for provider: {provider.name}"
                )
                return result
            else:
                result["found"] = False
                logging.info(
                    f"User not found based on Match keywords for provider: {provider.name}"
                )
                return result
        
        return result

    async def fetch_user_profile(
        self, user: str, current_provider: Provider, session: aiohttp.ClientSession
    ) -> Tuple[Optional[int], Optional[str]]:

        provider = current_provider
        method = provider.request_method or "GET"
        
        headers = {
            "User-Agent": self.ua.random,
        }
        if provider.headers:
            headers.update(provider.headers)

        payload = provider.build_payload(user) or {}

        if provider.query_url:
            url = provider.build_url(user, provider.query_url)
        else:
            url = provider.build_url(user)

        try:
            timeout = ClientTimeout(total=self.timeout)
            if method == "GET":
                logging.info(f"Fetching URL: {url}")
                async with session.get(
                    url, headers=headers, timeout=timeout, allow_redirects=True, proxy=self.proxy
                ) as resp:
                    text = await resp.text(errors='ignore')
                    logging.info(f"Response status code: {resp.status}")
                    return resp.status, text
            elif method.upper() == "POST":
                logging.info(f"Fetching URL: {url}")
                async with session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=True,
                    proxy=self.proxy
                ) as resp:
                    text = await resp.text(errors='ignore')
                    logging.info(f"Response status code: {resp.status}")
                    return resp.status, text
        except Exception as e:
            logging.error(f"Failed to fetch profile page for URL {url}: {e}")
            return None, None
        return None, None

    async def search_in_response(self, html: str, current_provider: Provider, session: aiohttp.ClientSession) -> dict:

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

        if not provider.is_connected:
            return result

        if provider.has_email:
            emails_set = self.search_info(html)["emails"]
            for email in emails_set:
                if email in self.found_emails:
                    result["infos"]["emails"][email] = self.found_emails[email]
                else:
                    if self.check_breach:
                        if self.hibp_key is not None:
                            check_res = await self.check_HaveIBeenPwned(email, session)
                            result["infos"]["emails"][email] = check_res[0]
                            result["infos"]["breach_count"][email] = check_res[1]
                        else:
                            result["infos"]["emails"][email] = await self.check_HudsonRock(email, session)
                        if result["infos"]["emails"][email] == True:
                            check_pass = await self.check_ProxyNova(email, session)
                            if check_pass is not None:
                                result["infos"]["passwords"][email] = check_pass
                    else:
                        result["infos"]["emails"][email] = False

        if provider.handle_regex:

            for prov_name in provider.handle_regex.keys():
                handle = provider.extract_handle(prov_name, html)
                if handle:
                    mactch_provider = self.all_providers.get(prov_name)
                    logging.debug(f"Matched provider: {prov_name},{mactch_provider}")
                    if not mactch_provider:
                        continue
                    if not mactch_provider.is_userid:
                        result["other_usernames"].add(handle)
                    links = mactch_provider.build_url(handle)
                    result["other_links"][prov_name] = [links]
            return result

        if hasattr(provider, "links") and provider.links:
            provs_to_search = [
                self.all_providers[name]
                for name in provider.links
                if name in self.all_providers
            ]
        else:
            provs_to_search = [
                p for pname, p in self.all_providers.items() if pname != provider.name
            ]

        result["other_links"] = self.search_new_links(html, provs_to_search)

        other_usernames_set = self.search_new_usernames(html, provs_to_search)

        result["other_usernames"].update(other_usernames_set)


        return result

    def search_new_links(
        self, html: str, provider_list: List[Provider]
    ) -> Dict[str, List[str]]:
        discovered = {}
        for prov in provider_list:
            matches = prov.extract_links(html)
            matches = matches
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

    async def check_HaveIBeenPwned(self, email: str, session: aiohttp.ClientSession) -> Tuple[bool, int]:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": self.hibp_key,
            "User-Agent": self.ua.random,
        }
        try:
            async with session.get(url, headers=headers, timeout=5) as res:
                status_code = res.status
                if status_code == 404:
                    return False, 0
                if status_code == 200:
                    data = await res.json()
                    breach_count = len(data)
                    return True, breach_count
        except Exception:
            return False, 0
        return False, 0

    async def check_HudsonRock(self, email: str, session: aiohttp.ClientSession) -> bool:
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}"
        associated_string = "This email address is associated with a computer that was infected by an info-stealer, all the credentials saved on this computer are at risk of being accessed by cybercriminals. Visit https://www.hudsonrock.com/free-tools to discover additional free tools and Infostealers related data."
        not_associated_string = "This email address is not associated with a computer infected by an info-stealer. Visit https://www.hudsonrock.com/free-tools to discover additional free tools and Infostealers related data."
        try:
            async with session.get(url, timeout=5) as res:
                status_code = res.status
                if status_code == 404:
                    return False
                if status_code == 200:
                    json_content = await res.json()
                    if json_content["message"] == associated_string:
                        return True
                    elif json_content["message"] == not_associated_string:
                        return False
        except Exception:
            return False
        return False

    async def check_ProxyNova(self, email: str, session: aiohttp.ClientSession) -> List[str]:
        url = f"https://api.proxynova.com/comb?query={email}"
        try:
            async with session.get(url, timeout=5) as res:
                if res.status == 404:
                    return None
                if res.status == 200:
                    json_content = await res.json()
                    lines = json_content.get("lines", [])
                    password_set = set()
                    prefix = f"{email}:"
                    for line in lines:
                        if line.startswith(prefix):
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                pass_part = parts[1].strip()
                                if pass_part:
                                    password_set.add(pass_part)
                    if password_set:
                        return list(password_set)
        except Exception:
            return None
            
        return None
