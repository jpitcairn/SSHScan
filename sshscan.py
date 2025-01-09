#!/usr/bin/env python3

import sys
import socket
import struct
import json
from yaml import safe_load
from typing import List, Tuple
from secrets import token_bytes
from binascii import hexlify
from optparse import OptionParser, OptionGroup
import pkg_resources

def banner():
    banner = r"""
      _____ _____ _    _ _____
     /  ___/  ___| | | /  ___|
     \ `--.\ `--.| |_| \ `--.  ___ __ _ _ __
      `--. \`--. |  _  |`--. \/ __/ _` | '_ \
     /\__/ /\__/ | | | /\__/ | (_| (_| | | | |
     \____/\____/\_| |_\____/ \___\__,_|_| |_|
                                            evict
    """
    return banner


def print_columns(item_list):
    """Prints a list in columns."""
    cols = 2
    while len(item_list) % cols != 0:
        item_list.append("")
    else:
        split = [
            item_list[i : i + int(len(item_list) / cols)]
            for i in range(0, len(item_list), int(len(item_list) / cols))
        ]
        for row in zip(*split):
            print("            " + "".join(str.ljust(c, 37) for c in row))
    print("\n")


def return_diff_list(detected, strong):
    """Returns items in 'detected' that are not in 'strong'."""
    results = []
    for item in detected:
        if item not in strong:
            results.append(item)
    return results


def parse_results(version, kex, salg, enc, mac, cmpv, options):
    """
    Parse the KEXINIT data, compare to config.yml, determine 'weak' entries.
    Return a dict with the results.
    """
    version = version.decode("utf-8").rstrip()
    kex = kex.decode("utf-8").split(",")
    salg = salg.decode("utf-8").split(",")
    enc = enc.decode("utf-8").split(",")
    mac = mac.decode("utf-8").split(",")
    cmpv = cmpv.decode("utf-8").split(",")

    # Load the "strong" config from config.yml in the same package
    with pkg_resources.resource_stream(__name__, "config.yml") as fd:
        config = safe_load(fd)

    # Determine what is "weak"
    weak_ciphers = return_diff_list(enc, config["ciphers"])
    weak_macs = return_diff_list(mac, config["macs"])
    weak_kex = return_diff_list(kex, config["kex"])
    weak_hka = return_diff_list(salg, config["hka"])

    # Check if compression is enabled
    compression_enabled = "zlib@openssh.com" in cmpv

    # Build a dictionary of results
    result_data = {
        "ssh_version": version,
        "detected": {
            "ciphers": enc,
            "kex": kex,
            "macs": mac,
            "hostkey_algos": salg,
            "compression_enabled": compression_enabled,
        },
        "weak": {
            "ciphers": weak_ciphers,
            "kex": weak_kex,
            "macs": weak_macs,
            "hostkey_algos": weak_hka,
        },
    }

    # Print to console, unless the user wants minimal output
    if not options.weak:
        print("    [+] Detected the following ciphers: ")
        print_columns(enc)
        print("    [+] Detected the following KEX algorithms: ")
        print_columns(kex)
        print("    [+] Detected the following MACs: ")
        print_columns(mac)
        print("    [+] Detected the following HostKey algorithms: ")
        print_columns(salg)
        print("    [+] Target SSH version is: %s" % version)
        print("    [+] Retrieving ciphers...")

    # Print any detected weaknesses
    if weak_ciphers:
        print("    [+] Detected the following weak ciphers: ")
        print_columns(weak_ciphers)
    else:
        print("    [+] No weak ciphers detected!")

    if weak_kex:
        print("    [+] Detected the following weak KEX algorithms: ")
        print_columns(weak_kex)
    else:
        print("    [+] No weak KEX detected!")

    if weak_macs:
        print("    [+] Detected the following weak MACs: ")
        print_columns(weak_macs)
    else:
        print("    [+] No weak MACs detected!")

    if weak_hka:
        print("    [+] Detected the following weak HostKey algorithms: ")
        print_columns(weak_hka)
    else:
        print("    [+] No weak HostKey algorithms detected!")

    if compression_enabled:
        print("    [+] Compression has been enabled!")

    return result_data


def unpack_ssh_name_list(kex, n):
    """
    Unpack the name-list from the packet. The comma-separated list is preceded
    by an unsigned integer specifying size of that list.
    """
    size = struct.unpack("!I", kex[n : n + 4])[0] + 1
    # jump to the name-list
    n += 3
    payload = struct.unpack(f"!{size}p", kex[n : n + size])[0]
    # next integer
    n += size
    return payload, n


def unpack_msg_kex_init(kex, options):
    """
    Parse the SSH_MSG_KEXINIT packet to retrieve KEX, host key algos,
    encryption algos, MAC, compression, etc.
    """
    packet_size = struct.unpack("!I", kex[0:4])[0]
    if not options.weak:
        print(f"[*] KEX size: {packet_size}")
    message = kex[5]  # 20 == SSH_MSG_KEXINIT
    if message != 20:
        raise ValueError("Did not receive SSH_MSG_KEXINIT!")

    cookie = struct.unpack("!16p", kex[6:22])[0]
    if not options.weak:
        print(f"[*] server cookie: {hexlify(cookie).decode('utf-8')}")

    kex_size = struct.unpack("!I", kex[22:26])[0] + 1
    kex_algos = struct.unpack(f"!{kex_size}p", kex[25 : 25 + kex_size])[0]
    n = 25 + kex_size

    server_host_key_algo, n = unpack_ssh_name_list(kex, n)
    enc_client_to_server, n = unpack_ssh_name_list(kex, n)
    enc_server_to_client, n = unpack_ssh_name_list(kex, n)
    mac_client_to_server, n = unpack_ssh_name_list(kex, n)
    mac_server_to_client, n = unpack_ssh_name_list(kex, n)
    cmp_client_to_server, n = unpack_ssh_name_list(kex, n)
    cmp_server_to_client, n = unpack_ssh_name_list(kex, n)

    return (
        kex_algos,
        server_host_key_algo,
        enc_server_to_client,    # ciphers
        mac_server_to_client,    # macs
        cmp_server_to_client,    # compression
    )


def retrieve_initial_kexinit(host: str, port: int) -> Tuple[bytes, bytes]:
    """
    Connect to the SSH server, read version, send it back,
    then read the KEXINIT packet.
    """
    s = return_socket_for_host(host, port)
    version = s.recv(2048)
    s.send(version)
    kex_init = s.recv(4096)
    s.close()
    return kex_init, version


def return_socket_for_host(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s


def generate_html_table(data):
    """
    Given the 'all_results' from scanning, generate an HTML table
    showing only the hosts that have ANY weak algorithms.
    
    We'll include columns: Host, Weak KEX, Weak Ciphers, Weak MACs.
    Each list item will be shown on its own line (<br>).
    """
    # 1. Gather only hosts with weaknesses
    hosts_with_weaknesses = []
    for item in data:
        weak_kex = item["weak"]["kex"]
        weak_ciphers = item["weak"]["ciphers"]
        weak_macs = item["weak"]["macs"]
        # If any are non-empty => "weak"
        if weak_kex or weak_ciphers or weak_macs:
            hosts_with_weaknesses.append({
                "host": item["host"],
                "weak_kex": weak_kex,
                "weak_ciphers": weak_ciphers,
                "weak_macs": weak_macs
            })

    # 2. Build the HTML table
    html_lines = []
    html_lines.append("<table>")
    html_lines.append("<tr><th>Host</th><th>Weak KEX</th><th>Weak Ciphers</th><th>Weak MAC</th></tr>")

    for host_data in hosts_with_weaknesses:
        kex_str = "<br>".join(host_data["weak_kex"])
        ciphers_str = "<br>".join(host_data["weak_ciphers"])
        macs_str = "<br>".join(host_data["weak_macs"])

        row = (
            f"<tr>"
            f"<td>{host_data['host']}</td>"
            f"<td>{kex_str}</td>"
            f"<td>{ciphers_str}</td>"
            f"<td>{macs_str}</td>"
            f"</tr>"
        )
        html_lines.append(row)

    html_lines.append("</table>")
    return "\n".join(html_lines)


def main():
    print(banner())

    parser = OptionParser(usage="usage %prog [options]", version="%prog 2.0")
    parameters = OptionGroup(parser, "Options")

    parameters.add_option(
        "-t",
        "--target",
        type="string",
        help="Specify target as 'target' or 'target:port' (port 22 is default)",
        dest="target",
    )
    parameters.add_option(
        "-l",
        "--target-list",
        type="string",
        help="File with targets: 'target' or 'target:port' separated by a newline (port 22 is default)",
        dest="targetlist",
    )
    parameters.add_option(
        "-w",
        "--weak",
        action="store_true",
        help="Only show weak ciphers in console output",
        dest="weak",
    )
    parameters.add_option(
        "--json",
        type="string",
        help="Save scan results as JSON to the specified file",
        dest="jsonfile",
    )
    parameters.add_option(
        "--html",
        type="string",
        help="Save an HTML table of hosts with weaknesses to the specified file",
        dest="htmlfile",
    )

    parser.add_option_group(parameters)
    options, arguments = parser.parse_args()

    # Gather targets
    targets = []
    if options.target:
        targets.append(options.target)
    elif options.targetlist:
        with open(options.targetlist, 'r') as fd:
            for line in fd:
                line = line.strip()
                if line:
                    targets.append(line)
    else:
        print("[-] No target specified!")
        sys.exit(0)

    all_results = []

    # Connect to each target, parse KEXINIT, store results
    for target in targets:
        if ":" not in target:
            target += ":22"

        host, port = target.split(":")
        port = int(port)

        print(f"\n[*] Now scanning {host}:{port}\n")

        try:
            kex_init, version = retrieve_initial_kexinit(host, port)
        except socket.timeout:
            print(f"    [-] Timeout while connecting to {host}:{port}\n")
            continue
        except socket.error as e:
            print(f"    [-] Error connecting to {host}:{port} => {e}\n")
            continue

        # parse the server KEXINIT message
        try:
            kex, salg, enc, mac, cmpv = unpack_msg_kex_init(kex_init, options)
        except ValueError as e:
            print(f"    [-] {e}\n")
            continue

        result_data = parse_results(version, kex, salg, enc, mac, cmpv, options)
        # Add host/port info
        result_data["host"] = host
        result_data["port"] = port

        all_results.append(result_data)

    if options.jsonfile:
        with open(options.jsonfile, 'w') as fd:
            json.dump(all_results, fd, indent=2)
        print(f"[+] JSON results written to: {options.jsonfile}")

    if options.htmlfile:
        html_table = generate_html_table(all_results)
        with open(options.htmlfile, "w") as fd:
            fd.write(html_table)
        print(f"[+] HTML table of weaknesses written to: {options.htmlfile}")

    print("\n[+] Scanning complete.")

if __name__ == "__main__":
    main()
