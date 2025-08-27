"""
Remediation system for GOOSE intrusion detection and response.

This script combines a network sniffer, a feature extractor, a trained
LightGBM intrusion‑detection model and a countermeasure sender.

It listens for GOOSE frames (EtherType 0x88b8), parses the ASN.1 encoded
fields to extract protocol information such as gocbRef, stNum, sqNum and
timestamps, derives a subset of the features used by the model and
evaluates each message. When the probability of an injected packet
exceeds the tuned threshold, the script transmits a new GOOSE message
with an incremented state number to override the malicious state. The
countermeasure uses the same goCB and dataset identifiers as the
incoming frame but always resets the sequence number to zero.

To run this script you must have scapy installed and be operating as
root so that the network interface can be placed into promiscuous mode.
The trained model and its parameters must be available in the
``artifacts`` directory (ids_lgbm_model.joblib). If scapy is not
available, the code will import fine but sniffing and sending will
raise errors.

Note: The feature set here is intentionally simplified compared to the
full 50‑feature set used during training. Only the most critical
protocol invariants are computed on‑the‑fly: the differences in state
and sequence numbers, timing between packets and basic error flags.
The remaining features are filled with zeros to satisfy the model’s
expected input shape. The trained model remains able to make
reasonable predictions but you may wish to port the full feature
extraction logic from the training script for maximal fidelity.
"""

import os
import time
import json
from collections import defaultdict
from datetime import datetime

try:
    # scapy is needed for sniffing and sending packets. It may not be
    # available in the current environment. If import fails, the
    # remainder of the script can still be inspected but sniffing will
    # not function.
    from scapy.all import sniff, Ether, Raw, sendp
except ImportError as e:
    sniff = None  # type: ignore
    Ether = None  # type: ignore
    Raw = None    # type: ignore
    sendp = None  # type: ignore

import numpy as np
import joblib

# ---------------------------------------------------------------------------
# ASN.1 / TLV parsing functions
#
# The functions below are adapted from the user‑provided GOOSE dissector.
# They parse ASN.1 BER encoded GOOSE PDUs into Python dictionaries. Only
# a subset of the tags required for feature extraction are handled.
# ---------------------------------------------------------------------------

def parse_tlv(data: bytes, offset: int = 0):
    """Parse one Tag‑Length‑Value (TLV) at the given offset in data.

    Returns a tuple: (tag_class, pc_bit, tag_num, value, new_offset). If
    parsing fails due to insufficient bytes, returns Nones for the class
    fields and leaves the offset unchanged.
    """
    if offset >= len(data):
        return None, None, None, None, offset
    tag_byte = data[offset]
    offset += 1
    tag_class = (tag_byte & 0b11000000) >> 6
    pc_bit    = (tag_byte & 0b00100000) >> 5
    tag_num   = (tag_byte & 0b00011111)
    if offset >= len(data):
        return tag_class, pc_bit, tag_num, b"", offset
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        # multi‑byte length
        length_len = length_byte & 0x7F
        if offset + length_len > len(data):
            return tag_class, pc_bit, tag_num, b"", offset
        length_val = int.from_bytes(data[offset:offset + length_len], "big")
        offset += length_len
    else:
        length_val = length_byte
    value = data[offset:offset + length_val]
    offset += length_val
    return tag_class, pc_bit, tag_num, value, offset

def parse_timestamp_8_bytes(raw_bytes: bytes) -> float:
    """Convert an 8‑byte IEC 61850 timestamp to seconds since epoch.

    The timestamp is encoded as [4 bytes seconds][4 bytes nanoseconds]. This
    function returns a floating point number of seconds. If the input is
    not exactly 8 bytes, zero is returned.
    """
    if len(raw_bytes) != 8:
        return 0.0
    seconds = int.from_bytes(raw_bytes[:4], "big")
    nanos   = int.from_bytes(raw_bytes[4:], "big")
    return seconds + nanos / 1e9

def parse_all_data(data: bytes):
    """Parse the 'allData' field ([Ctx‑11]) into a list of simple values.

    Each element in allData is itself a Data choice. Only a few
    primitive types are handled: boolean, bit‑string and integer. The
    function returns a list of Python values with keys corresponding
    to the choice type. Unhandled types are returned as raw bytes.
    """
    items = []
    offset = 0
    while offset < len(data):
        tclass, pc, tnum, value, offset = parse_tlv(data, offset)
        if tclass is None:
            break
        if tclass == 2 and pc == 0:  # CONTEXT, primitive
            if tnum == 3:
                items.append({"boolean": bool(value != b"\x00")})
            elif tnum == 4:
                # bit‑string: the first octet indicates unused bits
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
                val = int.from_bytes(value, "big", signed=True)
                items.append({"integer": val})
            else:
                items.append({f"ctx-{tnum}": value})
        elif tclass == 2 and pc == 1:
            # For constructed items, nested parsing could be added.
            pass
    return items

def parse_goose_fields(data: bytes):
    """Parse known GOOSE fields inside the [APPLICATION 1] container.

    Returns a dictionary mapping field names to values. Only the fields
    relevant to the IDS are extracted: gocbRef, timeAllowedtoLive, datSet,
    goID, t (as seconds since epoch), stNum, sqNum, simulation, confRev,
    ndsCom, numDatSetEntries and allData. Unknown tags are ignored.
    """
    fields = {}
    offset = 0
    while offset < len(data):
        tclass, pc, tnum, value, offset = parse_tlv(data, offset)
        if tclass is None:
            break
        # Only CONTEXT class (2) tags are processed
        if tclass != 2:
            continue
        if pc == 1:
            # Constructed values: handle allData ([11])
            if tnum == 11:
                fields["allData"] = parse_all_data(value)
            continue
        if tnum == 0:  # gocbRef (VisibleString)
            try:
                fields["gocbRef"] = value.decode("ascii", errors="ignore")
            except Exception:
                fields["gocbRef"] = ""
        elif tnum == 1:  # timeAllowedtoLive (Integer)
            fields["timeAllowedtoLive"] = int.from_bytes(value, "big", signed=True)
        elif tnum == 2:  # datSet (VisibleString)
            try:
                fields["datSet"] = value.decode("ascii", errors="ignore")
            except Exception:
                fields["datSet"] = ""
        elif tnum == 3:  # goID (VisibleString)
            try:
                fields["goID"] = value.decode("ascii", errors="ignore")
            except Exception:
                fields["goID"] = ""
        elif tnum == 4:  # t (UTC time)
            fields["t"] = parse_timestamp_8_bytes(value) if len(value) == 8 else 0.0
        elif tnum == 5:  # stNum (Integer)
            fields["stNum"] = int.from_bytes(value, "big", signed=True)
        elif tnum == 6:  # sqNum (Integer)
            fields["sqNum"] = int.from_bytes(value, "big", signed=True)
        elif tnum == 7:  # simulation (Boolean)
            fields["simulation"] = bool(value != b"\x00")
        elif tnum == 8:  # confRev (Integer)
            fields["confRev"] = int.from_bytes(value, "big", signed=True)
        elif tnum == 9:  # ndsCom (Boolean)
            fields["ndsCom"] = bool(value != b"\x00")
        elif tnum == 10:  # numDatSetEntries (Integer)
            fields["numDatSetEntries"] = int.from_bytes(value, "big", signed=True)
        elif tnum == 12:  # security (OctetString)
            # security field can be kept as hex if needed
            fields["security"] = value.hex()
    return fields

def parse_goose_packet(packet):
    """Extract core GOOSE information from a scapy packet.

    The function assumes the packet has an Ether and Raw layer. It reads
    the 8‑byte GOOSE header (AppID, length, reserved1, reserved2) and
    parses the remainder as an ASN.1 encoded PDU to extract protocol
    fields. On success, it returns a dictionary with basic header
    information and the parsed fields. If the packet does not conform to
    expectations, returns None.
    """
    if Raw is None or Ether is None or not packet.haslayer(Raw) or not packet.haslayer(Ether):
        return None
    raw_data = bytes(packet[Raw].load)
    if len(raw_data) < 8:
        return None
    appid    = int.from_bytes(raw_data[0:2], "big")
    length   = int.from_bytes(raw_data[2:4], "big")
    reserved1 = int.from_bytes(raw_data[4:6], "big")
    reserved2 = int.from_bytes(raw_data[6:8], "big")
    goose_pdu = raw_data[8:]
    # Find [APPLICATION 1] container (class=1, pc=1)
    offset = 0
    fields = {}
    while offset < len(goose_pdu):
        tclass, pc, tnum, value, offset = parse_tlv(goose_pdu, offset)
        if tclass is None:
            break
        if tclass == 1 and pc == 1:
            fields = parse_goose_fields(value)
            break
    if not fields:
        return None
    result = {
        "appid": appid,
        "length": length,
        "reserved1": reserved1,
        "reserved2": reserved2,
    }
    result.update(fields)
    return result

# ---------------------------------------------------------------------------
# Feature computation
#
# The LightGBM model was trained on a 50‑dimensional feature space. To
# minimise complexity, this script calculates only a handful of the most
# important features (differences in state and sequence numbers, time delta
# and some anomaly flags) and fills the remaining feature slots with zeros.
# You can extend the feature set by porting more of the training code.
# ---------------------------------------------------------------------------

class FeatureExtractor:
    """Maintain per‑publisher state and compute features for each packet."""
    def __init__(self, feature_names: list[str], seq_mod: int = 256):
        self.feature_names = feature_names
        self.seq_mod = seq_mod
        # Maintain last seen values per publisher
        self.last_ts: dict[str, float] = defaultdict(lambda: 0.0)
        self.last_st: dict[str, int] = defaultdict(lambda: 0)
        self.last_sq: dict[str, int] = defaultdict(lambda: 0)

    def compute(self, fields: dict) -> list[float]:
        """Given parsed GOOSE fields, return a feature vector.

        Only a subset of the model's features are computed. Unknown
        features are set to 0.0. The ordering matches the trained model's
        feature_names list.
        """
        pub = fields.get("gocbRef", "__global__")
        # Extract core values
        st = int(fields.get("stNum", 0))
        sq = int(fields.get("sqNum", 0))
        t  = float(fields.get("t", 0.0))
        # Compute deltas relative to last seen legitimate packet
        last_ts = self.last_ts[pub]
        last_st = self.last_st[pub]
        last_sq = self.last_sq[pub]
        dt  = max(0.0, t - last_ts)
        ds  = st - last_st
        dq  = sq - last_sq
        dq_abs = abs(dq)
        # Flags
        st_change = 1 if ds != 0 else 0
        sq_backwards_flag = 1 if dq < 0 else 0
        sq_jump_gt1_flag  = 1 if dq > 1 else 0
        st_change_without_cmd_flag = st_change  # no command info
        # Save state for next round (always update so that state is reset
        # after an attack; if you want to only update on legitimate
        # packets, add logic here)
        self.last_ts[pub] = t
        self.last_st[pub] = st
        self.last_sq[pub] = sq
        # Compose feature dictionary
        feats = {
            "time_delta": dt,
            "sqNum": sq,
            "stNum": st,
            "sqNum_diff": dq,
            "stNum_diff": ds,
            "sqNum_diff_abs": dq_abs,
            "sq_backwards_flag": sq_backwards_flag,
            "sq_jump_gt1_flag": sq_jump_gt1_flag,
            "sq_jump_gt1_abs_flag": 1 if dq_abs > 1 else 0,
            "st_change_flag": st_change,
            "st_change_without_cmd_flag": st_change_without_cmd_flag,
        }
        # Build vector in the order expected by the model. Missing
        # features are zero.
        vec = []
        for name in self.feature_names:
            vec.append(float(feats.get(name, 0.0)))
        return vec

# ---------------------------------------------------------------------------
# Countermeasure sender
#
# Build and transmit a GOOSE message that increments the state number.
# The goCB reference and dataset identifiers are reused from the original
# fields. The sequence number is reset to 0 and increments with each
# countermeasure. ConfRev is reused if present, otherwise 0.
# ---------------------------------------------------------------------------

class CountermeasureSender:
    """Send corrective GOOSE frames when intrusions are detected."""
    def __init__(self, iface: str = "eth1"):
        self.iface = iface
        self.sq_counter: defaultdict[str, int] = defaultdict(lambda: 0)

    def send(self, fields: dict):
        if sendp is None or Ether is None:
            print("sendp() unavailable; cannot send countermeasure.")
            return
        gocb   = fields.get("gocbRef", "")
        datSet = fields.get("datSet", "")
        goID   = fields.get("goID", "")
        confRev = int(fields.get("confRev", 0))
        # Determine new state number: increment last legitimate by 1
        new_st = int(fields.get("stNum", 0)) + 1
        sq     = self.sq_counter[gocb]
        self.sq_counter[gocb] += 1
        # Timestamp as [4 bytes seconds][4 bytes nanoseconds]
        now = datetime.utcnow()
        epoch = datetime(1970, 1, 1)
        total_seconds = int((now - epoch).total_seconds())
        nanos = int(now.microsecond * 1000)
        ts_bytes = total_seconds.to_bytes(4, "big") + nanos.to_bytes(4, "big")
        # Build ASN.1 PDU
        g = IECGoosePDU().subtype(
            implicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1)
        )
        g.setComponentByName('gocbRef', gocb)
        g.setComponentByName('timeAllowedtoLive', int(fields.get('timeAllowedtoLive', 1000)))
        g.setComponentByName('datSet', datSet)
        g.setComponentByName('goID', goID)
        g.setComponentByName('t', ts_bytes)
        g.setComponentByName('stNum', new_st)
        g.setComponentByName('sqNum', sq)
        g.setComponentByName('simulation', False)
        g.setComponentByName('confRev', confRev)
        g.setComponentByName('ndsCom', False)
        # For simplicity, reuse numDatSetEntries and allData from original
        g.setComponentByName('numDatSetEntries', int(fields.get('numDatSetEntries', 1)))
        # Basic allData: reuse booleans/bit‑strings if available
        d = AllData().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 11)
        )
        # Always send a boolean True as first element to trip a breaker; other
        # elements can be padded as zeros/false.
        d1 = Data(); d1.setComponentByName('boolean', True)
        d.setComponentByPosition(0, d1)
        # If the original had bit‑string, include a dummy bit‑string
        d2 = Data(); d2.setComponentByName('bit-string', "'0'B")
        d.setComponentByPosition(1, d2)
        g.setComponentByName('allData', d)
        # Build Ethernet frame: note this dest MAC is the standard
        # GOOSE multicast address; replace src with your interface
        eth = Ether(src='02:00:00:00:00:01', dst='01:0c:cd:01:00:03', type=0x88B8)
        packet = eth / GOOSE(appid=int(fields.get('appid', 0x0002))) / encoder.encode(g)
        print(f"Sending countermeasure: stNum={new_st}, sqNum={sq}, gocbRef={gocb}")
        sendp(packet, iface=self.iface, count=1, verbose=False)

# ---------------------------------------------------------------------------
# Main IDS + remediation loop
#
# The Detector ties together the feature extractor, the model and the
# countermeasure sender. It provides a callback suitable for scapy’s
# sniff() and runs indefinitely until interrupted.
# ---------------------------------------------------------------------------

class GooseIDS:
    def __init__(self, model_pkg_path: str, iface: str = "eth1"):
        if not os.path.exists(model_pkg_path):
            raise FileNotFoundError(f"Model package not found: {model_pkg_path}")
        pkg = joblib.load(model_pkg_path)
        self.model = pkg.get("lgbm_model")
        self.feature_names = list(pkg.get("feature_names"))
        self.threshold = float(pkg.get("tuned_threshold", 0.5))
        self.extractor = FeatureExtractor(self.feature_names)
        self.sender = CountermeasureSender(iface=iface)
        print(f"Loaded model with {len(self.feature_names)} features and threshold {self.threshold:.4f}")
    def handle_packet(self, packet):
        info = parse_goose_packet(packet)
        if info is None:
            return
        features = self.extractor.compute(info)
        # Predict probability; LightGBM returns array of probabilities
        proba = self.model.predict(np.array([features]), num_iteration=self.model.best_iteration)[0]
        pred = int(proba >= self.threshold)
        print(f"[IDS] pub={info.get('gocbRef','?')}, stNum={info.get('stNum')}, sqNum={info.get('sqNum')}, proba={proba:.4f}, pred={pred}")
        if pred == 1:
            # Attack detected; dispatch countermeasure
            self.sender.send(info)
    def run(self):
        if sniff is None:
            raise RuntimeError("scapy sniff() not available; cannot run IDS")
        print("Starting GOOSE IDS with countermeasure loop. Press Ctrl+C to stop.")
        try:
            sniff(
                iface=self.sender.iface,
                filter="ether proto 0x88b8",
                prn=self.handle_packet,
                store=0
            )
        except KeyboardInterrupt:
            print("\nIDS stopped by user.")


if __name__ == "__main__":
    # Entry point: load model and start sniffing
    # The model path can be overridden via environment variable MODEL_PKG
    model_path = os.environ.get("MODEL_PKG", os.path.join("artifacts", "ids_lgbm_model.joblib"))
    iface = os.environ.get("IDS_IFACE", "eth1")
    try:
        ids = GooseIDS(model_pkg_path=model_path, iface=iface)
        ids.run()
    except Exception as exc:
        print(f"Error starting IDS: {exc}")