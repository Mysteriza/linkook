import asyncio
import logging
import aiohttp

class ScannerManager:
    def __init__(self, user, scanner, console_printer, args):
        self.user = user
        self.scanner = scanner
        self.console_printer = console_printer
        self.args = args
        self.results = {}
        self.queue = asyncio.Queue()
        self.lock = asyncio.Lock() 
        self.visited_tasks = set() # Track (user, provider_name) to avoid duplicates in queue

    async def _process_provider(self, user, provider_name, other_links_flag, session):
        """
        process a provider and update the results (internal method)
        """
        
        provider = self.scanner.all_providers.get(provider_name)
        if not provider:
            return

        # deep scan
        scan_result = await self.scanner.deep_scan(user, provider, session)

        # print result
        if not self.args.silent:
            self.console_printer.update({
                "site_name": provider_name,
                "status": "FOUND" if scan_result["found"] else "NOT FOUND",
                "profile_url": scan_result["profile_url"],
                "other_links": scan_result.get("other_links", {}),
                "other_links_flag": other_links_flag,
                "infos": scan_result.get("infos", {}),
                "hibp": self.scanner.hibp_key,
            })

        # update results
        async with self.lock:
            self.results[provider_name] = scan_result
        

        # add new tasks
        other_links = scan_result.get("other_links", {})
        for linked_provider, linked_urls in other_links.items():
            linked_provider_obj = self.scanner.all_providers.get(linked_provider)
            if not linked_provider_obj or not linked_provider_obj.is_connected:
                continue
            for url in linked_urls:
                if url in self.scanner.visited_urls:
                    continue
                new_user = linked_provider_obj.extract_user(url).pop()
                if new_user != user:
                    task_key = (new_user, linked_provider)
                    if task_key not in self.visited_tasks:
                        self.visited_tasks.add(task_key)
                        await self.queue.put((new_user, linked_provider, True))

    async def _worker(self, session):
        """
        worker coroutine to process tasks from the queue
        """
        while True:
            try:
                # Get a "unit of work" from the queue.
                user, provider, flag = await self.queue.get()
                try:
                    await self._process_provider(user, provider, flag, session)
                except Exception as e:
                    logging.error(f"Error processing {provider}: {e}")
                finally:
                    self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"Worker error: {e}")

    async def run_scan(self):
        """
        run the scan and return the results
        """

        self.console_printer.start(self.user)
        
        for provider in self.scanner.to_scan:
            await self.queue.put((self.user, provider, False))
            self.visited_tasks.add((self.user, provider))

        # Create a single session for all requests
        async with aiohttp.ClientSession() as session:
            workers = []
            # Create workers (increase concurrency significantly compared to threads)
            num_workers = self.args.workers
            for _ in range(num_workers): 
                task = asyncio.create_task(self._worker(session))
                workers.append(task)

            # Wait until the queue is fully processed.
            await self.queue.join()

            # Cancel our worker tasks.
            for task in workers:
                task.cancel()
            
            # Wait until all worker tasks are cancelled.
            await asyncio.gather(*workers, return_exceptions=True)

        return self.results
