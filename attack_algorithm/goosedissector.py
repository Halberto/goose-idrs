#!/usr/bin/env python3

"""
GOOSE Protocol Packet Dissector
Author: Hermenegildo Alberto
Date: January 8, 2025
"""

from scapy.all import sniff, Ether, Raw
from datetime import datetime
import csv
import json

##############################################################################
# ANSI Color Helper Functions
##############################################################################
def colored(text, color="blue", style="bold"):
    """Wrap text in ANSI color/style codes."""
    styles = {
        "bold": "1",
        "dim": "2",
        "underline": "4",
        "blink": "5",
        "reverse": "7",
        "normal": "0"
    }
    colors = {
        "black": 30, "red": 31, "green": 32, "yellow": 33,
        "blue": 34, "magenta": 35, "cyan": 36, "white": 37
    }
    style_code = styles.get(style.lower(), "0")
    color_code = colors.get(color.lower(), 37)
    return f"\033[{style_code};{color_code}m{text}\033[0m"

def print_banner(title, width=60):
    """Print a simple ASCII banner with color."""
    bar = colored("=" * width, color="cyan", style="bold")
    centered = colored(title.center(width), color="cyan", style="bold")
    print(bar)
    print(centered)
    print(bar)

##############################################################################
# TLV Parsing Functions
##############################################################################
def parse_tlv(data, offset=0):
    """
    Parse one Tag-Length-Value (TLV) starting at 'offset' in 'data'.
    Returns: (tag_class, pc_bit, tag_num, value, new_offset).
    """
    if offset >= len(data):
        return None, None, None, None, offset

    tag_byte = data[offset]
    offset += 1
    tag_class = (tag_byte & 0b11000000) >> 6
    pc_bit = (tag_byte & 0b00100000) >> 5
    tag_num = (tag_byte & 0b00011111)

    if offset >= len(data):
        return tag_class, pc_bit, tag_num, b'', offset

    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        length_len = length_byte & 0x7F
        if offset + length_len > len(data):
            return tag_class, pc_bit, tag_num, b'', offset
        length_val = int.from_bytes(data[offset:offset + length_len], 'big')
        offset += length_len
    else:
        length_val = length_byte

    value = data[offset:offset + length_val]
    offset += length_val
    return tag_class, pc_bit, tag_num, value, offset

def parse_timestamp_8_bytes(raw_bytes):
    """
    Parse an 8-byte timestamp ([4 bytes seconds] + [4 bytes nanoseconds])
    and return a formatted string like "Feb 11, 2025 16:17:22.123456789 UTC".
    """
    if len(raw_bytes) != 8:
        return "Invalid timestamp"
    seconds = int.from_bytes(raw_bytes[:4], 'big')
    nanos = int.from_bytes(raw_bytes[4:], 'big')
    dt = datetime.utcfromtimestamp(seconds)
    return f"{dt.strftime('%b %d, %Y %H:%M:%S')}.{nanos:09d} UTC"

##############################################################################
# GOOSE Field Parsing (Known Fields)
##############################################################################
def parse_all_data(data):
    """
    Parse the 'allData' field ([Ctx-11]), which is typically a list of Data items.
    Returns a list of dictionaries.
    """
    items = []
    offset = 0
    while offset < len(data):
        tclass, pc, tnum, value, offset = parse_tlv(data, offset)
        if tclass is None:
            break
        if tclass == 2 and pc == 0:  # CONTEXT, primitive
            if tnum == 3:
                items.append({"boolean": (value != b'\x00')})
            elif tnum == 4:
                if len(value) > 0:
                    unused = value[0]
                    bit_bytes = value[1:]
                    bits_str = "".join(f"{byte:08b}" for byte in bit_bytes)
                    if 0 < unused <= 7:
                        bits_str = bits_str[:-unused]
                    items.append({"bit-string": bits_str})
                else:
                    items.append({"bit-string": ""})
            elif tnum == 5:
                val = int.from_bytes(value, 'big', signed=True)
                items.append({"integer": val})
            else:
                items.append({f"ctx-{tnum}": value.hex()})
        elif tclass == 2 and pc == 1:
            # For constructed items, you might extend parsing further.
            pass
    return items

def parse_goose_fields(data):
    """
    Parse known GOOSE fields inside the [APPLICATION 1] container.
    Returns a dictionary with key/value pairs.
    """
    fields = {}
    offset = 0
    while offset < len(data):
        tclass, pc, tnum, value, offset = parse_tlv(data, offset)
        if tclass is None:
            break
        # Process only CONTEXT (class 2) tags.
        if tclass != 2:
            continue
        if pc == 1:
            if tnum == 11:  # allData is constructed
                fields["allData"] = parse_all_data(value)
            continue
        if tnum == 0:  # gocbRef (VisibleString)
            fields["gocbRef"] = value.decode('ascii', errors='ignore')
        elif tnum == 1:  # timeAllowedtoLive (Integer)
            fields["timeAllowedtoLive"] = int.from_bytes(value, 'big', signed=True)
        elif tnum == 2:  # datSet (VisibleString)
            fields["datSet"] = value.decode('ascii', errors='ignore')
        elif tnum == 3:  # goID (VisibleString)
            fields["goID"] = value.decode('ascii', errors='ignore')
        elif tnum == 4:  # t (8-byte time)
            fields["utcTime"] = parse_timestamp_8_bytes(value) if len(value) == 8 else value.hex()
        elif tnum == 5:  # stNum (Integer)
            fields["stNum"] = int.from_bytes(value, 'big', signed=True)
        elif tnum == 6:  # sqNum (Integer)
            fields["sqNum"] = int.from_bytes(value, 'big', signed=True)
        elif tnum == 7:  # simulation (Boolean)
            fields["simulation"] = (value != b'\x00')
        elif tnum == 8:  # confRev (Integer)
            fields["confRev"] = int.from_bytes(value, 'big', signed=True)
        elif tnum == 9:  # ndsCom (Boolean)
            fields["ndsCom"] = (value != b'\x00')
        elif tnum == 10:  # numDatSetEntries (Integer)
            fields["numDatSetEntries"] = int.from_bytes(value, 'big', signed=True)
        elif tnum == 12:  # security (OctetString)
            fields["security"] = value.hex()
    return fields

##############################################################################
# Recursive TLV Tree Printer (Print All Data)
##############################################################################
def print_tlv_tree(data, indent=0):
    """
    Recursively print the entire TLV tree from 'data'.
    Every TLV is printed, even if not recognized.
    """
    offset = 0
    classes = {0: "UNIVERSAL", 1: "APPLICATION", 2: "CONTEXT", 3: "PRIVATE"}
    while offset < len(data):
        tclass, pc, tnum, value, new_offset = parse_tlv(data, offset)
        if tclass is None:
            break
        tag_class_str = classes.get(tclass, str(tclass))
        pc_str = "Constructed" if pc == 1 else "Primitive"
        print(" " * indent + f"[{tag_class_str} Tag {tnum}] ({pc_str}, len={len(value)})")
        if pc == 1:
            print_tlv_tree(value, indent + 2)
        else:
            try:
                ascii_val = value.decode('ascii')
                print(" " * (indent + 2) + f"Value: {ascii_val} (hex: {value.hex()})")
            except Exception:
                print(" " * (indent + 2) + f"Value (hex): {value.hex()}")
        offset = new_offset

##############################################################################
# Global list to store captured packet information for CSV output
##############################################################################
packets_captured = []

##############################################################################
# Main GOOSE Dissector (Scapy Callback)
##############################################################################
def dissect_goose(packet):
    if not packet.haslayer(Raw) or not packet.haslayer(Ether):
        return

    raw_data = bytes(packet[Raw].load)
    if len(raw_data) < 8:
        return

    # Parse the 8-byte GOOSE header.
    appid = int.from_bytes(raw_data[0:2], 'big')
    length = int.from_bytes(raw_data[2:4], 'big')
    reserved1 = int.from_bytes(raw_data[4:6], 'big')
    reserved2 = int.from_bytes(raw_data[6:8], 'big')
    goose_pdu = raw_data[8:]  # The ASN.1 encoded data.

    # Look for the top-level [APPLICATION 1] container.
    offset = 0
    fields = {}
    app_value = None
    while offset < len(goose_pdu):
        tclass, pc, tnum, value, offset = parse_tlv(goose_pdu, offset)
        if tclass is None:
            break
        if tclass == 1 and pc == 1:
            fields = parse_goose_fields(value)
            app_value = value  # Save the APPLICATION container value.
            break  # Stop after finding the container.

    # Print the summary banner and header info.
    print_banner("GOOSE PACKET DISSECTION", width=56)
    print(colored(f"  From: {packet[Ether].src} -> {packet[Ether].dst}", "yellow"))
    print(colored(f"  GOOSE length = {length}", "yellow"))
    print(colored(f"  Packet size  = {len(raw_data)}", "yellow"))
    print(colored(f"  Reserved1    = {reserved1}", "yellow"))
    print(colored(f"  Reserved2    = {reserved2}", "yellow"))
    print(colored(f"  AppID        = 0x{appid:04x} ({appid})", "yellow"))

    # Print known fields if available.
    if "gocbRef" in fields:
        print(colored(f"  CB Reference  = {fields['gocbRef']}", "green"))
    if "timeAllowedtoLive" in fields:
        print(colored(f"  TAL           = {fields['timeAllowedtoLive']} ms", "green"))
    if "datSet" in fields:
        print(colored(f"  DataSet Ref   = {fields['datSet']}", "green"))
    if "goID" in fields:
        print(colored(f"  GOOSE ID      = {fields['goID']}", "green"))
    if "utcTime" in fields:
        print(colored(f"  UtcTime       = {fields['utcTime']}", "green"))
    if "stNum" in fields:
        print(colored(f"  StNumber      = {fields['stNum']}", "green"))
    if "sqNum" in fields:
        print(colored(f"  SequenceNum   = {fields['sqNum']}", "green"))
    if "ndsCom" in fields:
        print(colored(f"  Needs Comms   = {int(fields['ndsCom'])}", "green"))
    if "confRev" in fields:
        print(colored(f"  Conf.Rev      = {fields['confRev']}", "green"))
    if "numDatSetEntries" in fields:
        print(colored(f"  No. of Elem.  = {fields['numDatSetEntries']}", "green"))

    # Print all objects in the allData field, if present.
    if "allData" in fields and isinstance(fields["allData"], list):
        for i, obj in enumerate(fields["allData"], start=1):
            print(colored(f"\n  Object: {i}", "magenta"))
            for key, value in obj.items():
                if key == "boolean":
                    print(colored(f"    Boolean: {value}", "cyan"))
                elif key == "bit-string":
                    spaced = " ".join(value[j:j + 4] for j in range(0, len(value), 4))
                    print(colored(f"    Bit-string: {spaced}", "cyan"))
                elif key == "integer":
                    print(colored(f"    Integer: {value}", "cyan"))
                else:
                    print(colored(f"    {key}: {value}", "cyan"))

    # Print the full TLV tree.
    print(colored("\nFull TLV Tree:", "magenta", "bold"))
    if app_value is not None:
        print_tlv_tree(app_value, indent=2)
    else:
        print_tlv_tree(goose_pdu, indent=2)

    print(colored("-" * 56, "cyan"))
    print()

    # Save parsed packet info into global list.
    # Here we serialize the "allData" field as a JSON string.
    packet_info = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "src": packet[Ether].src,
        "dst": packet[Ether].dst,
        "appid": appid,
        "length": length,
        "reserved1": reserved1,
        "reserved2": reserved2,
        "gocbRef": fields.get("gocbRef", ""),
        "timeAllowedtoLive": fields.get("timeAllowedtoLive", ""),
        "datSet": fields.get("datSet", ""),
        "goID": fields.get("goID", ""),
        "utcTime": fields.get("utcTime", ""),
        "stNum": fields.get("stNum", ""),
        "sqNum": fields.get("sqNum", ""),
        "ndsCom": fields.get("ndsCom", ""),
        "confRev": fields.get("confRev", ""),
        "numDatSetEntries": fields.get("numDatSetEntries", ""),
        # Serialize the allData field (if present) to a JSON string.
        "allData": json.dumps(fields.get("allData", ""))
    }
    packets_captured.append(packet_info)

##############################################################################
# Save Captured Data to CSV Function
##############################################################################
def save_to_csv(data, filename='capture.csv'):
    if not data:
        print("No data to save.")
        return
    # Determine CSV header based on union of all keys.
    header = sorted({key for d in data for key in d.keys()})
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=header)
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    print(f"Capture saved to {filename}")

##############################################################################
# Entry Point: Start Packet Sniffing
##############################################################################
if __name__ == "__main__":
    print(colored("Starting continuous GOOSE packet dissection (press Ctrl+C to stop)...", "yellow", "bold"))
    try:
        sniff(
            iface="eth1",  # Replace with your actual interface
            filter="ether proto 0x88b8",  # GOOSE Ethertype
            prn=dissect_goose,
            store=0
        )
    except KeyboardInterrupt:
        print(colored("\nCapture interrupted by user.", "red", "bold"))
    finally:
        save_to_csv(packets_captured)
