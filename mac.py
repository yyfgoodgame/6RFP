import ipaddress
import csv

def load_ipv6_addresses(ipv6_file):
    """Load IPv6 address file and return a list of addresses."""
    with open(ipv6_file, 'r') as f:
        ipv6_addresses = [line.strip() for line in f if line.strip()]
    return ipv6_addresses

def is_eui64_address(ipv6_addr):
    """Determine if an IPv6 address is generated using the EUI-64 method.

    If the interface identifier contains 'FFFE' in the middle, it is considered an EUI-64 address.
    """
    try:
        # Convert the string to an IPv6Address object
        addr = ipaddress.IPv6Address(ipv6_addr)
        # Get the interface identifier (last 64 bits)
        interface_id = addr.packed[-8:]
        # Check if the middle 2 bytes are FFFE
        if interface_id[3:5] == b'\xFF\xFE':
            return True
        else:
            return False
    except ipaddress.AddressValueError:
        # Invalid IPv6 address
        return False

def extract_mac_from_ipv6(ipv6_addr):
    """Extract MAC address from an EUI-64 generated IPv6 address.

    Returns the MAC address in standard format, e.g., 'AA-BB-CC-DD-EE-FF'.
    """
    addr = ipaddress.IPv6Address(ipv6_addr)
    interface_id = addr.packed[-8:]
    # Extract the first 3 bytes and the last 3 bytes of the MAC address
    mac_bytes = interface_id[:3] + interface_id[5:]
    # Flip the 7th bit (Universal/Local bit) of the first byte
    mac_bytes = bytearray(mac_bytes)
    mac_bytes[0] ^= 0x02
    # Format the MAC address as a standard string
    mac_str = '-'.join('{:02X}'.format(b) for b in mac_bytes)
    return mac_str

def load_oui_data(oui_csv_file):
    """Load OUI CSV file and create a mapping dictionary from OUI to manufacturer name."""
    oui_dict = {}
    with open(oui_csv_file, 'r', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile, delimiter='\t')
        next(reader)  # Skip the header
        for row in reader:
            if len(row) >= 3:
                oui = row[1].replace('-', '').replace(':', '').upper()
                manufacturer = row[2].strip()
                oui_dict[oui] = manufacturer
        return oui_dict

def match_manufacturers(ipv6_addresses, oui_dict):
    """Match manufacturers and return lists of EUI-64 addresses, corresponding MAC addresses, and matching results."""
    eui64_addresses = []
    mac_addresses = []
    results = []
    for ipv6_addr in ipv6_addresses:
        if is_eui64_address(ipv6_addr):
            eui64_addresses.append(ipv6_addr)
            mac_addr = extract_mac_from_ipv6(ipv6_addr)
            mac_addresses.append(mac_addr)
            # Extract OUI (first 6 characters without separators)
            oui = mac_addr.replace('-', '')[:6]
            if oui in oui_dict:
                manufacturer = oui_dict[oui]
                results.append((ipv6_addr, mac_addr, manufacturer))
    return eui64_addresses, mac_addresses, results

def save_mac_addresses(mac_addresses, mac_file):
    """Save the extracted MAC addresses to a file."""
    with open(mac_file, 'w', encoding='utf-8') as f:
        for mac_addr in mac_addresses:
            f.write(f'{mac_addr}\n')

def save_results(results, output_file):
    """Save the matched IPv6 addresses, MAC addresses, and manufacturer names to a file."""
    with open(output_file, 'w', encoding='utf-8') as f:
        for ipv6_addr, mac_addr, manufacturer in results:
            f.write(f'{ipv6_addr}\t{mac_addr}\t{manufacturer}\n')

def main():
    """Main function that integrates all functionalities."""
    ipv6_file = 'itdk_address.txt'         # Input IPv6 address file
    oui_csv_file = 'oui.csv'               # OUI CSV file
    eui64_file = 'itdk_address_eui.txt'    # Save initially found EUI-64 addresses
    mac_file = 'mac_addresses.txt'         # Save extracted MAC addresses
    output_file = 'eui64_manufacturers.txt'  # Save matching results

    # Load data
    ipv6_addresses = load_ipv6_addresses(ipv6_file)
    oui_dict = load_oui_data(oui_csv_file)

    # Match manufacturers
    eui64_addresses, mac_addresses, results = match_manufacturers(ipv6_addresses, oui_dict)

    # Save initially found EUI-64 addresses
    save_eui64_addresses(eui64_addresses, eui64_file)

    # Save extracted MAC addresses
    save_mac_addresses(mac_addresses, mac_file)

    # Save matching results
    save_results(results, output_file)

    # Output processing information
    print(f'Processing completed. Found {len(eui64_addresses)} EUI-64 addresses, {len(results)} matched with manufacturer info.')
    print(f'Initially found EUI-64 addresses saved to {eui64_file}.')
    print(f'Extracted MAC addresses saved to {mac_file}.')
    print(f'Matching results saved to {output_file}.')

def save_eui64_addresses(eui64_addresses, eui64_file):
    """Save the initially found EUI-64 addresses to a file."""
    with open(eui64_file, 'w', encoding='utf-8') as f:
        for ipv6_addr in eui64_addresses:
            f.write(f'{ipv6_addr}\n')

if __name__ == '__main__':
    main()
