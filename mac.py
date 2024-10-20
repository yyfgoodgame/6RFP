import ipaddress
import csv

def load_ipv6_addresses(ipv6_file):
    """加载 IPv6 地址文件，返回地址列表。"""
    with open(ipv6_file, 'r') as f:
        ipv6_addresses = [line.strip() for line in f if line.strip()]
    return ipv6_addresses

def is_eui64_address(ipv6_addr):
    """判断 IPv6 地址是否是通过 EUI-64 方法生成的。

    如果接口标识符的中间包含 'FFFE'，则认为是 EUI-64 地址。
    """
    try:
        # 将字符串转换为 IPv6Address 对象
        addr = ipaddress.IPv6Address(ipv6_addr)
        # 获取接口标识符（后 64 位）
        interface_id = addr.packed[-8:]
        # 检查中间的 2 个字节是否为 FFFE
        if interface_id[3:5] == b'\xFF\xFE':
            return True
        else:
            return False
    except ipaddress.AddressValueError:
        # 非法的 IPv6 地址
        return False

def extract_mac_from_ipv6(ipv6_addr):
    """从 EUI-64 生成的 IPv6 地址中提取 MAC 地址。

    返回标准格式的 MAC 地址字符串，如 'AA-BB-CC-DD-EE-FF'。
    """
    addr = ipaddress.IPv6Address(ipv6_addr)
    interface_id = addr.packed[-8:]
    # 提取 MAC 地址的前 3 个字节和后 3 个字节
    mac_bytes = interface_id[:3] + interface_id[5:]
    # 将第一个字节的第 7 位（Universal/Local 位）取反
    mac_bytes = bytearray(mac_bytes)
    mac_bytes[0] ^= 0x02
    # 构造标准格式的 MAC 地址字符串
    mac_str = '-'.join('{:02X}'.format(b) for b in mac_bytes)
    return mac_str

def load_oui_data(oui_csv_file):
    """加载 OUI CSV 文件，创建 OUI 到厂商名称的映射字典。"""
    oui_dict = {}
    with open(oui_csv_file, 'r', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile, delimiter='\t')
        next(reader)  # 跳过表头
        for row in reader:
            if len(row) >= 3:
                oui = row[1].replace('-', '').replace(':', '').upper()
                manufacturer = row[2].strip()
                oui_dict[oui] = manufacturer
        return oui_dict

def match_manufacturers(ipv6_addresses, oui_dict):
    """匹配厂商，返回 EUI-64 地址列表、对应的 MAC 地址列表和匹配结果列表。"""
    eui64_addresses = []
    mac_addresses = []
    results = []
    for ipv6_addr in ipv6_addresses:
        if is_eui64_address(ipv6_addr):
            eui64_addresses.append(ipv6_addr)
            mac_addr = extract_mac_from_ipv6(ipv6_addr)
            mac_addresses.append(mac_addr)
            # 提取 OUI（前 6 个字符，不含分隔符）
            oui = mac_addr.replace('-', '')[:6]
            if oui in oui_dict:
                manufacturer = oui_dict[oui]
                results.append((ipv6_addr, mac_addr, manufacturer))
    return eui64_addresses, mac_addresses, results

def save_mac_addresses(mac_addresses, mac_file):
    """将提取的 MAC 地址保存到文件。"""
    with open(mac_file, 'w', encoding='utf-8') as f:
        for mac_addr in mac_addresses:
            f.write(f'{mac_addr}\n')

def save_results(results, output_file):
    """将匹配到的 IPv6 地址、MAC 地址和厂商名称保存到文件。"""
    with open(output_file, 'w', encoding='utf-8') as f:
        for ipv6_addr, mac_addr, manufacturer in results:
            f.write(f'{ipv6_addr}\t{mac_addr}\t{manufacturer}\n')

def main():
    """总函数，整合所有功能。"""
    ipv6_file = 'itdk_address.txt'         # 输入的 IPv6 地址文件
    oui_csv_file = 'oui.csv'                 # OUI CSV 文件
    eui64_file = 'itdk_address_eui.txt'       # 保存初次找到的 EUI-64 地址
    mac_file = 'mac_addresses.txt'           # 保存提取的 MAC 地址
    output_file = 'eui64_manufacturers.txt'  # 保存匹配结果

    # 加载数据
    ipv6_addresses = load_ipv6_addresses(ipv6_file)
    oui_dict = load_oui_data(oui_csv_file)

    # 匹配厂商
    eui64_addresses, mac_addresses, results = match_manufacturers(ipv6_addresses, oui_dict)

    # 保存初次找到的 EUI-64 地址
    save_eui64_addresses(eui64_addresses, eui64_file)

    # 保存提取的 MAC 地址
    save_mac_addresses(mac_addresses, mac_file)

    # 保存匹配结果
    save_results(results, output_file)

    # 输出处理信息
    print(f'已处理完毕，共找到 {len(eui64_addresses)} 个 EUI-64 地址，其中 {len(results)} 个匹配到厂商信息。')
    print(f'初次找到的 EUI-64 地址已保存到 {eui64_file}。')
    print(f'提取的 MAC 地址已保存到 {mac_file}。')
    print(f'匹配结果已保存到 {output_file}。')

def save_eui64_addresses(eui64_addresses, eui64_file):
    """将初次找到的 EUI-64 地址保存到文件。"""
    with open(eui64_file, 'w', encoding='utf-8') as f:
        for ipv6_addr in eui64_addresses:
            f.write(f'{ipv6_addr}\n')

if __name__ == '__main__':
    main()
