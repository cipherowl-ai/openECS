#!/usr/bin/env python3

import argparse
import time
import asyncio
import aiohttp
import statistics
from datetime import datetime
import sys
from collections import defaultdict

class LoadTester:
    def __init__(self, url, duration, concurrency, headers=None):
        self.url = url
        self.duration = duration
        self.concurrency = concurrency
        self.headers = headers or {}
        self.results = []
        self.status_counts = defaultdict(int)
        self.request_count = 0
        self.start_time = None
        self.end_time = None

    async def make_request(self, session):
        start = time.time()
        try:
            async with session.get(self.url, headers=self.headers) as response:
                await response.text()
                end = time.time()
                latency = (end - start) * 1000  # Convert to ms
                self.results.append(latency)
                self.status_counts[response.status] += 1
                return True
        except Exception as e:
            end = time.time()
            latency = (end - start) * 1000  # Convert to ms
            self.results.append(latency)
            self.status_counts['error'] += 1
            return False

    async def worker(self, session):
        while time.time() < self.end_time:
            await self.make_request(session)
            self.request_count += 1

    async def run(self):
        self.start_time = time.time()
        self.end_time = self.start_time + self.duration
        
        print(f"Starting load test for {self.url}")
        print(f"Duration: {self.duration} seconds, Concurrency: {self.concurrency}")
        print("-" * 50)
        
        connector = aiohttp.TCPConnector(limit=self.concurrency)
        async with aiohttp.ClientSession(connector=connector) as session:
            workers = [self.worker(session) for _ in range(self.concurrency)]
            
            # Print progress while test is running
            progress_task = asyncio.create_task(self.show_progress())
            
            # Start all workers
            await asyncio.gather(*workers)
            
            # Cancel progress display
            progress_task.cancel()
            
        # Calculate and display final results
        self.print_results()

    async def show_progress(self):
        try:
            while True:
                elapsed = time.time() - self.start_time
                if elapsed > 0:
                    rate = self.request_count / elapsed
                    sys.stdout.write(f"\rRequests: {self.request_count}, Rate: {rate:.2f} req/sec")
                    sys.stdout.flush()
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            pass

    def print_results(self):
        actual_duration = time.time() - self.start_time
        
        print("\n" + "-" * 50)
        print("Test Results:")
        print(f"Total requests: {self.request_count}")
        print(f"Test duration: {actual_duration:.2f} seconds")
        print(f"Requests per second: {self.request_count / actual_duration:.2f}")
        
        if self.results:
            print("\nLatency (ms):")
            print(f"  Min: {min(self.results):.2f}")
            print(f"  Max: {max(self.results):.2f}")
            print(f"  Avg: {statistics.mean(self.results):.2f}")
            print(f"  Median: {statistics.median(self.results):.2f}")
            
            # Calculate percentiles
            sorted_latencies = sorted(self.results)
            p95_idx = int(len(sorted_latencies) * 0.95)
            p99_idx = int(len(sorted_latencies) * 0.99)
            
            print(f"  95th percentile: {sorted_latencies[p95_idx]:.2f}")
            print(f"  99th percentile: {sorted_latencies[p99_idx]:.2f}")
        
        print("\nStatus Codes:")
        for status, count in sorted(self.status_counts.items()):
            print(f"  {status}: {count} ({count/self.request_count*100:.2f}%)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Load Testing Tool")
    parser.add_argument("--url", default="http://localhost:8080/check?address=0xE5a00E3FccEfcCd9e4bA75955e12b6710eB254bE", 
                        help="URL to test")
    parser.add_argument("--duration", type=int, default=10, 
                        help="Test duration in seconds")
    parser.add_argument("--concurrency", type=int, default=10, 
                        help="Number of concurrent connections")
    args = parser.parse_args()
    
    # Custom headers
    headers = {
        "__llm_bot_caller__": "1"
    }
    
    tester = LoadTester(args.url, args.duration, args.concurrency, headers)
    asyncio.run(tester.run())