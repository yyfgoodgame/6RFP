import json
import threading
from scapy.all import *
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, IPv6
from scapy.layers.inet import TCP, UDP

# Input and output filenames
input_filename = "ripe_scapy_v6_results_701_ip_uni.txt"
output_filename = "ripe_scapy_v6_results_701_ip_uni_scapy.json"

# Read the target IPv6 address list
with open(input_filename, "r") as file:
    target_ips = [line.strip() for line in file.readlines()]

# Get the local IPv6 address
local_ip = get_if_addr6(conf.iface)

# Stateless ICMPv6 probe
def icmpv6_probe(target_ip, results):
    print(f"Probing ICMPv6: {target_ip}")
    packet = IPv6(src=local_ip, dst=target_ip)/ICMPv6EchoRequest()
    response = sr1(packet, timeout=2, verbose=False)
    if response:
        results["icmpv6"] = {
            "ttl": response[IPv6].hlim,
            "size": len(response),
            "type": response[ICMPv6EchoReply].type if ICMPv6EchoReply in response else None,
            "code": response[ICMPv6EchoReply].code if ICMPv6EchoReply in response else None,
            "response_received": True
        }
    else:
        results["icmpv6"] = {
            "ttl": None,
            "size": None,
            "type": None,
            "code": None,
            "response_received": False
        }

# Stateless TCP SYN probe
def tcp_probe(target_ip, results):
    print(f"Probing TCP: {target_ip}")
    packet = IPv6(src=local_ip, dst=target_ip)/TCP(dport=80, flags="S")
    response = sr1(packet, timeout=2, verbose=False)
    if response:
        results["tcp"] = {
            "ttl": response[IPv6].hlim,
            "size": len(response),
            "window_size": response[TCP].window if TCP in response else None,
            "flags": response.sprintf("%TCP.flags%"),
            "response_received": True
        }
    else:
        results["tcp"] = {
            "ttl": None,
            "size": None,
            "window_size": None,
            "flags": None,
            "response_received": False
        }

# Stateless UDP detection
def udp_probe(target_ip, results):
    print(f"Probing UDP: {target_ip}")
    packet = IPv6(src=local_ip, dst=target_ip)/UDP(dport=53)
    response = sr1(packet, timeout=2, verbose=False)
    if response:
        results["udp"] = {
            "ttl": response[IPv6].hlim,
            "size": len(response),
            "response_received": True
        }
    else:
        results["udp"] = {
            "ttl": None,
            "size": None,
            "response_received": False
        }

# Batch processing function
def process_batch(batch):
    batch_results = {}
    threads = []
    try:
        for target_ip in batch:
            batch_results[target_ip] = {}
            t1 = threading.Thread(target=icmpv6_probe, args=(target_ip, batch_results[target_ip]))
            t2 = threading.Thread(target=tcp_probe, args=(target_ip, batch_results[target_ip]))
            t3 = threading.Thread(target=udp_probe, args=(target_ip, batch_results[target_ip]))
            threads.extend([t1, t2, t3])
            t1.start()
            t2.start()
            t3.start()

        for thread in threads:
            thread.join()

    except KeyboardInterrupt:
        print("KeyboardInterrupt detected. Saving current batch results...")

    return batch_results

# Batch Processing
batch_size = 1000 
total_results = {}

for i in range(0, len(target_ips), batch_size):
    batch = target_ips[i:i + batch_size]
    batch_results = process_batch(batch)
    total_results.update(batch_results)

    with open(output_filename, "w") as json_file:
        json.dump(total_results, json_file, indent=4)

print(f"Probe results saved to {output_filename}")


