#!/usr/bin/env python3

import argparse
import time
import asyncio
import aiohttp
import statistics
from datetime import datetime
import sys
from collections import defaultdict
import random

class LoadTester:
    def __init__(self, addresses, duration, concurrency, headers):
        self.addresses = addresses
        self.duration = duration
        self.concurrency = concurrency
        self.headers = headers
        self.start_time = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.total_time = 0
        self.latencies = []
        self.status_counts = defaultdict(int)
        self.last_progress_time = 0
        self.progress_interval = 0.5  # Update progress every 0.5 seconds

    async def make_request(self, session):
        # Randomly select an address from the list
        address = random.choice(self.addresses)
        url = f"http://localhost:8080/check?address={address}"
        
        start_time = time.time()
        try:
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    self.successful_requests += 1
                else:
                    self.failed_requests += 1
                self.status_counts[response.status] += 1
        except Exception as e:
            self.failed_requests += 1
            self.status_counts['error'] += 1
            print(f"\nError: {e}")
        finally:
            latency = (time.time() - start_time) * 1000  # Convert to ms
            self.latencies.append(latency)
            self.total_time += latency / 1000  # Convert back to seconds
            self.total_requests += 1

    async def show_progress(self):
        while time.time() - self.start_time < self.duration:
            current_time = time.time()
            if current_time - self.last_progress_time >= self.progress_interval:
                elapsed = current_time - self.start_time
                if elapsed > 0:
                    rps = self.total_requests / elapsed
                    success_rate = (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0
                    sys.stdout.write(f"\rProgress: {elapsed:.1f}/{self.duration}s | "
                                   f"Requests: {self.total_requests} | "
                                   f"Rate: {rps:.1f} req/s | "
                                   f"Success: {success_rate:.1f}% | "
                                   f"Errors: {self.failed_requests}")
                    sys.stdout.flush()
                self.last_progress_time = current_time
            await asyncio.sleep(0.1)

    async def worker(self, session):
        while time.time() - self.start_time < self.duration:
            await self.make_request(session)

    async def run(self):
        print(f"\nStarting load test with {len(self.addresses)} addresses")
        print(f"Duration: {self.duration} seconds, Concurrency: {self.concurrency}")
        print("-" * 80)
        
        self.start_time = time.time()
        async with aiohttp.ClientSession() as session:
            # Start progress display
            progress_task = asyncio.create_task(self.show_progress())
            
            # Start workers
            tasks = [self.worker(session) for _ in range(self.concurrency)]
            await asyncio.gather(*tasks)
            
            # Cancel progress display
            progress_task.cancel()
            print("\n" + "-" * 80)

        # Calculate statistics
        total_time = time.time() - self.start_time
        rps = self.total_requests / total_time
        success_rate = (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0

        # Print detailed results
        print("\nTest Results:")
        print("-" * 80)
        print(f"Duration: {total_time:.2f} seconds")
        print(f"Total Requests: {self.total_requests:,}")
        print(f"Successful Requests: {self.successful_requests:,} ({success_rate:.1f}%)")
        print(f"Failed Requests: {self.failed_requests:,}")
        print(f"Requests per Second: {rps:.1f}")
        
        if self.latencies:
            print("\nLatency Statistics (ms):")
            print(f"  Min: {min(self.latencies):.2f}")
            print(f"  Max: {max(self.latencies):.2f}")
            print(f"  Avg: {statistics.mean(self.latencies):.2f}")
            print(f"  Median: {statistics.median(self.latencies):.2f}")
            
            # Calculate percentiles
            sorted_latencies = sorted(self.latencies)
            p95_idx = int(len(sorted_latencies) * 0.95)
            p99_idx = int(len(sorted_latencies) * 0.99)
            print(f"  95th percentile: {sorted_latencies[p95_idx]:.2f}")
            print(f"  99th percentile: {sorted_latencies[p99_idx]:.2f}")
        
        print("\nStatus Codes:")
        for status, count in sorted(self.status_counts.items()):
            percentage = (count / self.total_requests * 100) if self.total_requests > 0 else 0
            print(f"  {status}: {count:,} ({percentage:.1f}%)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Load Testing Tool")
    parser.add_argument("--file", "-f", required=True,
                        help="File containing addresses (one per line)")
    parser.add_argument("--duration", type=int, default=10, 
                        help="Test duration in seconds")
    parser.add_argument("--concurrency", type=int, default=10, 
                        help="Number of concurrent connections")
    args = parser.parse_args()
    
    # Read addresses from file
    try:
        with open(args.file, 'r') as f:
            addresses = [line.strip() for line in f if line.strip()]
        if not addresses:
            print(f"Error: No addresses found in {args.file}")
            exit(1)
        print(f"Loaded {len(addresses):,} addresses from {args.file}")
    except FileNotFoundError:
        print(f"Error: File {args.file} not found")
        exit(1)
    
    # Custom headers
    headers = {
        "__llm_bot_caller__": "0"
    }
    
    tester = LoadTester(addresses, args.duration, args.concurrency, headers)
    asyncio.run(tester.run())