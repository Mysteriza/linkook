# linkook/outputer/result_writer.py

import os
import logging
from typing import Dict, Any, Optional


class ResultWriter:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.ensure_output_directory()

    def ensure_output_directory(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            logging.info(f"Created output directory at: {self.output_dir}")
        else:
            logging.debug(f"Output directory already exists at: {self.output_dir}")

    def write_txt(self, username: str, results: Dict[str, Dict[str, Any]], ai_summary: Optional[str] = None):
        result_file = os.path.join(self.output_dir, f"{username}.txt")
        try:
            with open(result_file, "w", encoding="utf-8") as file:
                file.write(f"Results for username: {username}\n\n")
                found_counter = 0
                for site, data in results.items():
                    if not data.get("found"):
                        continue
                    
                    status = "FOUND"
                    file.write(f"Site: {site}\n")
                    file.write(f"Profile URL: {data['profile_url']}\n")
                    file.write(f"Status: {status}\n")

                    if "other_links" in data and data["other_links"]:
                        file.write("Linked Accounts:\n")
                        for provider, urls in data["other_links"].items():
                            if isinstance(urls, list):
                                urls_str = ", ".join(urls)
                            else:
                                urls_str = urls
                            file.write(f"- {provider}: {urls_str}\n")

                    if data["error"]:
                        file.write(f"Error: {data['error']}\n")
                    file.write("\n")
                    found_counter += 1
                
                if ai_summary:
                    file.write("====================== AI Persona Analysis ======================\n\n")
                    file.write(ai_summary)

            print(f"\nSaved result for {username} to {result_file}")
        except Exception as e:
            logging.error(f"Failed to write TXT results for {username}: {e}")

    def should_print_not_found(self) -> bool:
        return True