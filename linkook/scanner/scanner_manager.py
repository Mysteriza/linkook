# linkook/scanner/scanner_manager.py

import queue
import threading

exit_event = threading.Event()

def set_exiting():
    exit_event.set()

class ScannerManager:
    def __init__(self, user, scanner, console_printer, args):
        self.user = user
        self.scanner = scanner
        self.console_printer = console_printer
        self.args = args
        self.results = {}
        self.num_threads = 5
        self.queue = queue.Queue()
        self.lock = threading.Lock()
        self.processed_tasks = set()

    def _process_provider(self, user, provider_name, other_links_flag):
        task_id = (user.lower(), provider_name)
        with self.lock:
            if task_id in self.processed_tasks:
                return
            self.processed_tasks.add(task_id)

        if exit_event.is_set():
            return
        
        provider = self.scanner.all_providers.get(provider_name)
        if not provider:
            return

        scan_result = self.scanner.deep_scan(user, provider)

        if scan_result["found"]:
            with self.lock:
                self.results[provider_name] = scan_result
            
            if not self.args.silent:
                self.console_printer.update({
                    "site_name": provider_name,
                    "status": "FOUND",
                    "profile_url": scan_result["profile_url"],
                    "other_links": scan_result.get("other_links", {}),
                    "other_links_flag": other_links_flag,
                    "infos": scan_result.get("infos", {}),
                    "hibp": self.scanner.hibp_key,
                    "extracted_data": scan_result.get("extracted_data", {})
                })

        other_links = scan_result.get("other_links", {})
        for linked_provider, linked_urls in other_links.items():
            linked_provider_obj = self.scanner.all_providers.get(linked_provider)
            if not linked_provider_obj:
                continue
            
            urls_to_scan = linked_urls if isinstance(linked_urls, list) else [linked_urls]
            for url in urls_to_scan:
                if url in self.scanner.visited_urls:
                    continue
                
                extracted_users = linked_provider_obj.extract_user(url)
                if not extracted_users:
                    continue
                new_user = extracted_users.pop()
                
                new_task_id = (new_user.lower(), linked_provider)
                if new_task_id not in self.processed_tasks:
                    self.queue.put((new_user, linked_provider, True))

    def _worker(self):
        while not exit_event.is_set():
            try:
                user, provider, flag = self.queue.get(block=True, timeout=1)
                try:
                    self._process_provider(user, provider, flag)
                finally:
                    self.queue.task_done()
            except queue.Empty:
                break 
            except Exception as e:
                logging.error(f"Worker error: {e}")

    def run_scan(self):
        self.console_printer.start(self.user)
        
        for provider in self.scanner.to_scan:
            self.queue.put((self.user, provider, False))

        threads = []
        
        for _ in range(self.num_threads): 
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            threads.append(t)

        self.queue.join()

        for t in threads:
            t.join()

        return self.results