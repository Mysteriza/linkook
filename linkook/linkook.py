# linkook.py

import os
import sys
import getpass
import requests
import argparse
import subprocess
import importlib.metadata

import signal
import logging
from colorama import Fore, Style
from colorama import init as colorama_init

from linkook.scanner.site_scanner import SiteScanner
from linkook.outputer.result_writer import ResultWriter
from linkook.outputer.console_printer import ConsolePrinter
from linkook.outputer.visualize_output import Neo4jVisualizer
from linkook.provider.provider_manager import ProviderManager
from linkook.outputer.console_printer import CustomHelpFormatter
from linkook.scanner.scanner_manager import ScannerManager, set_exiting
from linkook.ai.persona_analyzer import PersonaAnalyzer

PACKAGE_NAME = "linkook"

def setup_logging(debug: bool):
    if debug:
        level = logging.DEBUG
        logging.basicConfig(
            level=level,
            format="[%(asctime)s] %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    else:
        logging.disable(logging.CRITICAL)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        usage=argparse.SUPPRESS, formatter_class=CustomHelpFormatter
    )
    parser.add_argument(
        "username", 
        nargs="?", 
        default=None, 
        help="Username to check across social networks."
    )
    parser.add_argument(
        "--version", 
        "-v", 
        action="store_true", 
        help="Show current version and check for updates."
    )
    parser.add_argument(
        "--update", 
        "-u", 
        action="store_true", 
        help="Update this tool via pipx if a newer version is available."
    )
    parser.add_argument(
        "--concise", "-c", 
        action="store_true", 
        help="Print more concise results."
    )
    parser.add_argument(
        "--silent",
        "-s",
        action="store_true",
        help="Suppress all output and only show summary.",
    )
    parser.add_argument(
        "--show-summary",
        "-ss",
        action="store_true",
        help="Show a summary of the scan results.",
    )
    parser.add_argument(
        "--check-breach",
        "-cb",
        action="store_true",
        help="Check if the username has been involved in a data breach, using data from HudsonRock's Cybercrime Intelligence Database.",
    )
    parser.add_argument(
        "--hibp",
        action="store_true",
        help="Use the Have I Been Pwned API to check if the username has been involved in a data breach.",
    )
    parser.add_argument(
        "--browse",
        "-b",
        action="store_true",
        dest="browse",
        default=False,
        help="Browse to all found profiles in the default browser.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
        default=False,
        help="Don't color terminal output.",
    )
    parser.add_argument(
        "--neo4j",
        action="store_true",
        help="Export the results to a JSON file for Neo4j visualization.",
    )
    parser.add_argument(
        "--scan-all",
        "-a",
        action="store_true",
        help="Scan all available sites in the provider.json file. If not set, only scan sites with 'isConnected' set to true.",
    )
    parser.add_argument(
        "--print-all",
        action="store_true",
        dest="print_all",
        default=False,
        help="Output sites where the username was not found.",
    )
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Enable verbose logging for debugging.",
    )
    parser.add_argument(
        "--output",
        "-o",
        nargs="?",
        metavar="PATH",
        const="results",
        help="Directory to save the results. Default is 'results'.",
    )
    parser.add_argument(
        "--local",
        "-l",
        nargs="?",
        metavar="PATH",
        const="provider.json",
        default="linkook/provider/provider.json",
        help="Force the use of the local provider.json file, add a custom path if needed. Default is 'provider.json'.",
    )
    parser.add_argument(
        "--groqAI",
        metavar="API_KEY",
        type=str,
        default=None,
        help="Enable AI Persona Analysis with your Groq API key."
    )
    return parser.parse_args()


def create_output_directory(output_dir: str):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logging.info(f"Created output directory at: {output_dir}")
    else:
        logging.info(f"Using existing output directory at: {output_dir}")

def check_version_from_pypi(package_name: str) -> str:
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return data["info"]["version"]
    except Exception as e:
        return None
    return None

def show_version():
    try:
        current_version = importlib.metadata.version(PACKAGE_NAME)
        message = f"{PACKAGE_NAME} version: {current_version}"
        latest_version = check_version_from_pypi(PACKAGE_NAME)
        if latest_version is None:
            message += f", could not check for updates."
            print(message)
            return

        if current_version == latest_version:
            message += f", you are up-to-date."
            print(message)
        else:
            message += f", a newer version is available: {latest_version}"
            print(message)
    except importlib.metadata.PackageNotFoundError:
        print(f"{PACKAGE_NAME} is running from source. Version check skipped.")


def check_update(verbose: bool) -> bool:
    print(f"{Fore.CYAN}Checking for updates...{Style.RESET_ALL}", end='', flush=True)
    latest_version = check_version_from_pypi(PACKAGE_NAME)
    if latest_version is None:
        if verbose:
            print(f"{Fore.YELLOW}\rCould not determine latest version from PyPI.{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}\rChecking for updates...{Fore.YELLOW}Error{Style.RESET_ALL}")
        return False
    
    try:
        current_version = importlib.metadata.version(PACKAGE_NAME)
        if current_version == latest_version:
            if verbose:
                print(f"{Fore.GREEN}\rYou are already running the latest version: {Style.BRIGHT}{latest_version}.{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}\rChecking for updates...{Fore.GREEN}OK{Style.RESET_ALL}")
            return False
        else:
            if verbose:
                print(f"{Fore.CYAN}\rNew version available: {Fore.GREEN}{Style.BRIGHT}{latest_version}{Style.RESET_ALL}{Fore.CYAN}. Updating via pipx...{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}\rNew version available: {Fore.GREEN}{Style.BRIGHT}{latest_version}.{Style.RESET_ALL}")
            return True
    except importlib.metadata.PackageNotFoundError:
        if verbose:
            print(f"{Fore.MAGENTA}\rCannot detect current version. Attempting to upgrade anyway.{Style.RESET_ALL}")
            return True
        else:
            print(f"\r{Fore.CYAN}Checking for updates...{Fore.YELLOW}Skipped (running from source){Style.RESET_ALL}")
            return False


def update_tool():
    need_update = check_update(verbose=True)

    if not need_update:
        return

    cmd = ["pipx", "upgrade", PACKAGE_NAME]
    try:
        subprocess.check_call(cmd)
        print(f"{Fore.GREEN}Successfully upgraded with pipx.{Style.RESET_ALL}")
    except FileNotFoundError:
        print(f"{Fore.YELLOW}{Style.BRIGHT}pipx{Style.RESET_ALL} {Fore.MAGENTA}not found. Please install pipx or update manually.{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Failed to update via pipx: {e}{Style.RESET_ALL}")

def get_hibp_key():
    hibp_key_path = os.path.expanduser("~/.hibp.key")
    
    if os.path.exists(hibp_key_path):
        with open(hibp_key_path, "r") as f:
            hibp_key = f.read().strip()
            if hibp_key:
                status = check_hibp_key(hibp_key)
                if status is True:
                    return hibp_key
                
                elif status is None:
                    return None
            else:
                print(f"\r{Fore.YELLOW}The stored 'Have I Been Pwned' API key is empty.{Style.RESET_ALL}")

    hibp_key = getpass.getpass(f"\r{Fore.CYAN}Please enter your 'Have I Been Pwned' API key (Input Hidden): {Style.RESET_ALL}")
    if not hibp_key:
        print(f"{Fore.RED}No API key provided. Exiting.{Style.RESET_ALL}")
        sys.exit(1)
    status = check_hibp_key(hibp_key)
    if status is False:
        sys.exit(1)
    if status is None:
        return None
    with open(hibp_key_path, "w") as f:
        f.write(hibp_key.strip())
        print(f"{Fore.CYAN}HIBP API key saved to {hibp_key_path}{Style.RESET_ALL}")

    return hibp_key

def check_hibp_key(hibp_key: str):
    url = "https://haveibeenpwned.com/api/v3/subscription/status"
    headers = {
            "hibp-api-key": hibp_key,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
        }
    try:
        print(f"{Fore.CYAN}\rChecking Have I Been Pwned API key...{Style.RESET_ALL}", end='', flush=True)
        resp = requests.get(url, timeout=5, headers=headers)
        if resp.status_code == 200:
            print(f"{Fore.CYAN}\rChecking Have I Been Pwned API key...{Fore.GREEN}OK{Style.RESET_ALL}")
            return True
        if resp.status_code == 401:
            print(f"{Fore.RED}\rInvalid HIBP API key! Please check your key.{Style.RESET_ALL}")
            return False
        else:
            print(f"{Fore.YELLOW}\rUnexpected error checking HIBP API key: {Fore.RED}{resp.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}\rError checking HIBP API key. Using HudsonRock's Database instead.{Style.RESET_ALL}")
    return None

def handler(signal_received, frame):
    print(f"\n{Fore.YELLOW}Process interrupted. Exiting...{Style.RESET_ALL}")
    set_exiting()
    sys.exit(0)

def scan_queue(user, scanner, console_printer, args):
    signal.signal(signal.SIGINT, handler)
    scanner_manager = ScannerManager(user, scanner, console_printer, args)
    return scanner_manager.run_scan()

def main():
    signal.signal(signal.SIGINT, handler)

    args = parse_arguments()
    if args.version:
        show_version()
        sys.exit(0)
    
    if args.update:
        update_tool()
        sys.exit(0) 

    if not args.username:
        print(f"{Fore.RED}Please provide a username to scan.{Style.RESET_ALL}")
        sys.exit(1)

    setup_logging(args.debug)

    if not args.no_color:
        colorama_init(autoreset=True)
    else:
        colorama_init(strip=True, convert=False)

    if not args.local:
        force_local = False
    else:
        force_local = True

    console_printer = ConsolePrinter(
        debug=args.debug,
        print_all=args.print_all,
        silent=args.silent,
        concise=args.concise,
        browse=args.browse,
    )

    console_printer.banner()

    check_update(verbose=False)

    setCheckBreach = False
    hibp_key = None

    if args.check_breach:
        setCheckBreach = True

    if args.hibp:
        setCheckBreach = True
        hibp_key = get_hibp_key()

    manager = ProviderManager(
        remote_json_url="https://raw.githubusercontent.com/JackJuly/linkook/refs/heads/main/linkook/provider/provider.json",
        local_json_path=args.local,
        force_local=force_local,
        timeout=10,
    )

    try:
        all_providers = manager.load_providers()
        logging.info(f"Loaded {len(all_providers)} providers.")
    except Exception as e:
        logging.error(f"Failed to load providers: {e}")
        sys.exit(1)

    scanner = SiteScanner(timeout=5, proxy=None)
    scanner.all_providers = all_providers
    scanner.to_scan = manager.filter_providers(is_connected=not args.scan_all)
    scanner.check_breach = setCheckBreach
    scanner.hibp_key = hibp_key

    username = args.username
    results = scan_queue(username, scanner, console_printer, args)

    extracted_data_by_platform = {}
    for platform, result in results.items():
        if result.get("found") and result.get("extracted_data"):
            extracted_data_by_platform[platform] = result["extracted_data"]

    print_content = {
        "username": username,
        "found_accounts": scanner.found_accounts,
        "found_usernames": scanner.found_usernames,
        "found_emails": scanner.found_emails,
        "found_passwords": scanner.found_passwords,
        "breach_count": scanner.breach_count,
        "all_providers": all_providers,
        "extracted_data": extracted_data_by_platform
    }

    if args.silent:
        args.show_summary = True

    console_printer.finish_all(print_content, args.show_summary)
    
    ai_summary_text = None
    if args.groqAI:
        analyzer = PersonaAnalyzer(api_key=args.groqAI)
        ai_summary_text = analyzer.analyze_persona(print_content)
        console_printer.print_ai_summary(ai_summary_text)

    if args.neo4j:
        visualizer = Neo4jVisualizer(results)
        visualizer.all_providers = all_providers
        visualizer.visualize(username=username, output_file="neo4j_export.json")

    result_writer = None
    if args.output is not None:
        output_name = args.output
        create_output_directory(output_name)
        result_writer = ResultWriter(output_name)

    if result_writer is not None:
        result_writer.write_txt(username, results, ai_summary=ai_summary_text)

    if args.browse:
        console_printer.browse_results(results)


if __name__ == "__main__":
    main()