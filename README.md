# Multi-Threaded Network IDS

## Overview:
A lightweight, high-throughput Intrusion Detection System (IDS) capable of sniffing, parsing, and analyzing network traffic in real-time. Designed to detect specific attack vectors including ARP Cache Poisoning, SYN Flooding, and Blacklisted URL access.

## Key Technical Features

**Producer-Consumer Architecture**: Decouples packet capture (latency-sensitive) from analysis (CPU-intensive) using a shared queue.
**Thread Pool**: Implements a fixed pool of worker threads (pthreads) to handle high-traffic loads without system resource exhaustion.
**Zero-Copy & Deep Copy Memory Management**: Handles volatile libpcap buffers safely by implementing deep-copy logic for the producer and rigorous memory cleanup in consumers (Verified leak-free via Valgrind).
**Concurrency Control**: Uses Mutexes and Condition Variables to prevent race conditions on shared statistical counters and the job queue.
**Graceful Shutdown**: Custom signal handling to ensure all pending packets are processed before termination.

### Attacks Detected

**SYN Flood**: Tracks unique source IPs using dynamic array resizing (realloc) to distinguish DDOS attacks from normal traffic.
**ARP Poisoning**: Inspects Ethernet/ARP headers for unsolicited replies.
**HTTP Inspection**: Parses TCP payloads to detect blacklisted domains on Port 80.

## What I learnt
I learnt a lot about the C programming level and low level architecture including memory management.
I also learnt about networks and the network stack as well as how packets are structured and transmitted across networks.
I also understood the sorts of attack vectors that could be used to damage network functionality.
