"""
Enhanced GOOSE IDSR with Real-time XAI and Improved Attack Detection Reporting.

Key enhancements:
1. Multi-stage detection (early warning + confirmation)
2. Real-time XAI explanations
3. Detailed timestamps and attack progression tracking
4. Enhanced reporting with attack timeline analysis
"""

import os
import re
import argparse
import time
import json
import socket
import logging
from logging.handlers import SysLogHandler
from datetime import datetime, timezone
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict, is_dataclass
from typing import Dict, List, Optional, Tuple
import sys

import numpy as np
import joblib

# Third-party dependencies (same as original)
try:
    from scapy.all import sniff, Ether, Raw, sendp
except Exception:
    sniff = None
    Ether = None
    Raw = None
    sendp = None

# ASN.1 helpers (same as original)
try:
    from pyasn1.type import tag
    from pyasn1.codec.ber import encoder
    from goose.goose_pdu import IECGoosePDU, AllData, Data
    from goose_.goose import GOOSE
except Exception:
    tag = None
    encoder = None
    IECGoosePDU = None
    AllData = None
    Data = None
    GOOSE = None

# =============================================================================
#                         TLV / GOOSE Parsing (BER) - Copied from original
# =============================================================================

def parse_tlv(data: bytes, offset: int = 0):
    if offset >= len(data):
        return None, None, None, None, offset
    tag_byte = data[offset]
    offset += 1
    tag_class = (tag_byte & 0b11000000) >> 6
    pc_bit    = (tag_byte & 0b00100000) >> 5
    tag_num   = (tag_byte & 0b00011111)

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

def parse_timestamp_8_bytes(raw_bytes: bytes) -> float:
    if len(raw_bytes) != 8:
        return 0.0
    seconds = int.from_bytes(raw_bytes[:4], 'big')
    nanos   = int.from_bytes(raw_bytes[4:], 'big')
    return float(seconds) + float(nanos) / 1e9

def parse_all_data(data: bytes):
    items = []
    offset = 0
    while offset < len(data):
        tclass, pc, tnum, value, offset = parse_tlv(data, offset)
        if tclass is None:
            break
        if tclass == 2 and pc == 0:
            if tnum == 3:
                items.append({"boolean": (value != b'\x00')})
            elif tnum == 4:
                if len(value):
                    unused = value[0]
                    bits = ''.join(f'{b:08b}' for b in value[1:])
                    if 0 < unused <= 7:
                        bits = bits[:-unused]
                    items.append({"bit-string": bits})
                else:
                    items.append({"bit-string": ""})
            elif tnum == 5:
                items.append({"integer": int.from_bytes(value, 'big', signed=True)})
            else:
                items.append({f"ctx-{tnum}": value})
    return items

def parse_goose_fields(data: bytes):
    fields = {}
    offset = 0
    while offset < len(data):
        tclass, pc, tnum, value, offset = parse_tlv(data, offset)
        if tclass is None:
            break
        if tclass != 2:
            continue
        if pc == 1:
            if tnum == 11:
                fields["allData"] = parse_all_data(value)
            continue
        if tnum == 0:
            fields["gocbRef"] = value.decode('ascii', errors='ignore')
        elif tnum == 1:
            fields["timeAllowedtoLive"] = int.from_bytes(value, 'big', signed=True)
        elif tnum == 2:
            fields["datSet"] = value.decode('ascii', errors='ignore')
        elif tnum == 3:
            fields["goID"] = value.decode('ascii', errors='ignore')
        elif tnum == 4:
            fields["t"] = parse_timestamp_8_bytes(value) if len(value) == 8 else 0.0
        elif tnum == 5:
            fields["stNum"] = int.from_bytes(value, 'big', signed=True)
        elif tnum == 6:
            fields["sqNum"] = int.from_bytes(value, 'big', signed=True)
        elif tnum == 7:
            fields["simulation"] = (value != b'\x00')
        elif tnum == 8:
            fields["confRev"] = int.from_bytes(value, 'big', signed=True)
        elif tnum == 9:
            fields["ndsCom"] = (value != b'\x00')
        elif tnum == 10:
            fields["numDatSetEntries"] = int.from_bytes(value, 'big', signed=True)
        elif tnum == 12:
            fields["security"] = value.hex()
    return fields

def parse_goose_packet(pkt):
    if Raw is None or Ether is None or not pkt.haslayer(Raw) or not pkt.haslayer(Ether):
        return None
    raw_data = bytes(pkt[Raw].load)
    if len(raw_data) < 8:
        return None
    appid    = int.from_bytes(raw_data[0:2], 'big')
    length   = int.from_bytes(raw_data[2:4], 'big')
    reserved1 = int.from_bytes(raw_data[4:6], 'big')
    reserved2 = int.from_bytes(raw_data[6:8], 'big')
    goose_pdu = raw_data[8:]

    fields = {}
    offset = 0
    while offset < len(goose_pdu):
        tclass, pc, tnum, value, offset = parse_tlv(goose_pdu, offset)
        if tclass is None:
            break
        if tclass == 1 and pc == 1:
            fields = parse_goose_fields(value)
            break
    if not fields:
        return None
    info = {
        "appid": appid,
        "length": length,
        "reserved1": reserved1,
        "reserved2": reserved2,
        "t": fields.get("t", float(getattr(pkt, "time", 0.0))),
    }
    info.update(fields)
    return info

# =============================================================================
#          Streaming Feature Extractor - Copied from original
# =============================================================================

SEQ_MOD = 256
WIN = 10
WIN_LONG = 100

EXPECTED_44 = [
    'time_delta', 'time_delta_zscore', 'sqNum', 'stNum',
    'sqNum_diff', 'stNum_diff', 'sqNum_diff_abs', 'stNum_diff_abs',
    'sq_backwards_flag', 'sq_jump_gt1_flag', 'sq_jump_gt1_abs_flag',
    'sq_backwards_mag', 'sq_jump_mag',
    'st_change_flag', 'st_change_with_cmd_flag', 'st_change_without_cmd_flag',
    'sqNum_rolling_mean', 'sqNum_rolling_std', 'sqNum_rolling_median', 'sqNum_deviation',
    'stNum_rolling_mean', 'stNum_rolling_std', 'stNum_rolling_median', 'stNum_deviation',
    'sq_frac_pos1', 'sq_frac_gt1', 'sq_frac_backwards', 'st_change_rate',
    'sqNum_consistency', 'stNum_consistency', 'unique_seq_patterns', 'unique_state_patterns',
    'sq_circ_diff', 'sq_wrap_flag', 'sq_incons_flag',
    'sq_incons_count_w100', 'sq_backwards_count_w100', 'sq_jump_abs_count_w100',
    'sq_frac_pos1_w100', 'sq_residual_abs_sum_w100', 'sq_circ_diff_std_w100',
    'st_injected_count_w100', 'st_change_count_w100', 'st_change_rate_w100'
]

DT_GUARDS = [
    "dt_in_baseline_flag", "dt_below_baseline", "dt_above_baseline",
    "dt_in_pub_baseline_flag", "dt_above_pub_baseline", "dt_below_pub_baseline"
]

def _std(vals):
    n = len(vals)
    if n <= 1:
        return 0.0
    m = sum(vals)/n
    return ((sum((v-m)*(v-m) for v in vals) / n) ** 0.5)

def _frac(bools):
    n = len(bools)
    return (sum(1 for x in bools if x) / n) if n else 0.0

class _PubState:
    def __init__(self):
        self.last_t = None
        self.last_sq = None
        self.last_st = None
        self.sq_hist = deque(maxlen=WIN_LONG)
        self.st_hist = deque(maxlen=WIN_LONG)
        self.sq_diff_hist = deque(maxlen=WIN_LONG)
        self.st_diff_hist = deque(maxlen=WIN_LONG)
        self.dt_hist = deque(maxlen=WIN_LONG)
        self.cmd_hist = deque(maxlen=WIN_LONG)
        self.sq_circ_diff_hist = deque(maxlen=WIN_LONG)
        self.sq_residual_hist = deque(maxlen=WIN_LONG)

class StreamingFeatureExtractor:
    def __init__(self, q_lo_ms: float, q_hi_ms: float, debug_feats: bool = False):
        self.pub_state: dict[str, _PubState] = {}
        self.q_lo_ms = float(q_lo_ms)
        self.q_hi_ms = float(q_hi_ms)
        self.global_dt = deque(maxlen=WIN_LONG)
        self.debug = debug_feats

    def _state(self, pub: str) -> _PubState:
        s = self.pub_state.get(pub)
        if s is None:
            s = _PubState()
            self.pub_state[pub] = s
        return s

    def _extract_cmd_bool(self, allData):
        if isinstance(allData, list) and allData:
            for it in allData:
                if isinstance(it, dict) and "boolean" in it:
                    return 1 if it["boolean"] else 0
            for it in allData:
                if isinstance(it, dict) and "bit-string" in it:
                    bits = it["bit-string"]
                    if isinstance(bits, str):
                        return 1 if '1' in bits else 0
        return 0

    def make_features(self, pkt_time_s: float, publisher_id: str, sqNum: int, stNum: int, allData):
        s = self._state(publisher_id)

        if s.last_t is None:
            dt = 0.0
        else:
            dt = max(0.0, float(pkt_time_s - s.last_t))
        s.last_t = float(pkt_time_s)
        dt_ms = dt * 1000.0

        self.global_dt.append(dt)
        if len(self.global_dt) >= 2:
            m = sum(self.global_dt)/len(self.global_dt)
            sd = _std(self.global_dt) or 1.0
            time_delta_zscore = abs((dt - m) / sd)
        else:
            time_delta_zscore = 0.0

        sq_diff = 0 if s.last_sq is None else int(sqNum - s.last_sq)
        st_diff = 0 if s.last_st is None else int(stNum - s.last_st)

        s.last_sq = int(sqNum)
        s.last_st = int(stNum)

        sq_diff_abs = abs(sq_diff)
        st_diff_abs = abs(st_diff)

        sq_backwards_flag = 1 if sq_diff < 0 else 0
        sq_jump_gt1_flag = 1 if sq_diff > 1 else 0
        sq_jump_gt1_abs_flag = 1 if abs(sq_diff) > 1 else 0
        sq_backwards_mag = (-sq_diff) if sq_diff < 0 else 0
        sq_jump_mag = abs(sq_diff)

        st_change_flag = 1 if st_diff != 0 else 0
        cmd = self._extract_cmd_bool(allData)
        st_change_with_cmd_flag = 1 if (st_change_flag == 1 and cmd == 1) else 0
        st_change_without_cmd_flag = 1 if (st_change_flag == 1 and cmd == 0) else 0

        s.sq_hist.append(int(sqNum))
        s.st_hist.append(int(stNum))
        s.sq_diff_hist.append(int(sq_diff))
        s.st_diff_hist.append(int(st_diff))
        s.dt_hist.append(float(dt_ms))
        s.cmd_hist.append(int(cmd))

        sq_tail = list(s.sq_hist)[-WIN:]
        st_tail = list(s.st_hist)[-WIN:]
        sq_diff_tail = list(s.sq_diff_hist)[-WIN:]
        st_diff_tail = list(s.st_diff_hist)[-WIN:]

        if sq_tail:
            sq_mean = float(sum(sq_tail)/len(sq_tail))
            sq_std = _std(sq_tail)
            sq_med = float(sorted(sq_tail)[len(sq_tail)//2]) if len(sq_tail)%2==1 else float((sorted(sq_tail)[len(sq_tail)//2-1] + sorted(sq_tail)[len(sq_tail)//2])/2)
        else:
            sq_mean = sq_std = sq_med = 0.0
        sq_dev = abs(int(sqNum) - sq_med)

        if st_tail:
            st_mean = float(sum(st_tail)/len(st_tail))
            st_std = _std(st_tail)
            st_med = float(sorted(st_tail)[len(st_tail)//2]) if len(st_tail)%2==1 else float((sorted(st_tail)[len(st_tail)//2-1] + sorted(st_tail)[len(st_tail)//2])/2)
        else:
            st_mean = st_std = st_med = 0.0
        st_dev = abs(int(stNum) - st_med)

        sq_frac_pos1 = _frac([d == 1 for d in sq_diff_tail])
        sq_frac_gt1 = _frac([abs(d) > 1 for d in sq_diff_tail])
        sq_frac_backwards = _frac([d < 0 for d in sq_diff_tail])
        st_change_rate = _frac([d != 0 for d in st_diff_tail])

        sqNum_consistency = sq_frac_pos1
        stNum_consistency = _frac([d == 1 for d in st_diff_tail])

        unique_seq_patterns = _std([abs(d) for d in sq_diff_tail])
        unique_state_patterns = _std([abs(d) for d in st_diff_tail])

        if len(s.sq_hist) >= 2:
            prev_sq = s.sq_hist[-2]
            sq_circ_diff = int((int(sqNum) - int(prev_sq)) % SEQ_MOD)
        else:
            sq_circ_diff = 0
        sq_wrap_flag = 1 if (sq_circ_diff < abs(sq_diff)) else 0
        sq_incons_flag = 1 if (abs(sq_diff) != 1 or abs(st_diff) > 1) else 0

        s.sq_circ_diff_hist.append(int(sq_circ_diff))
        s.sq_residual_hist.append(abs(int(sqNum) - sq_med))

        last_sqd = list(s.sq_diff_hist)[-WIN_LONG:]
        last_std = list(s.st_diff_hist)[-WIN_LONG:]

        last_incons = [1 if (abs(d)!=1 or abs(sd)>1) else 0 for d, sd in zip(last_sqd, last_std)]
        sq_incons_count_w100 = int(sum(last_incons))
        sq_backwards_count_w100 = int(sum(1 for d in last_sqd if d < 0))
        sq_jump_abs_count_w100 = int(sum(1 for d in last_sqd if abs(d) > 1))
        sq_frac_pos1_w100 = _frac([abs(d) == 1 for d in last_sqd])
        sq_residual_abs_sum_w100 = float(sum(list(s.sq_residual_hist)[-WIN_LONG:]))
        sq_circ_diff_std_w100 = _std(list(s.sq_circ_diff_hist)[-WIN_LONG:])
        st_change_count_w100 = int(sum(1 for d in last_std if d != 0))
        st_change_rate_w100 = _frac([d != 0 for d in last_std])
        st_injected_count_w100 = int(sum(1 for d, c in zip(last_std, list(s.cmd_hist)[-WIN_LONG:]) if d != 0 and c == 0))

        dt_in_baseline_flag = 1 if (self.q_lo_ms <= dt_ms <= self.q_hi_ms) else 0
        dt_below_baseline   = 1 if (dt_ms < self.q_lo_ms) else 0
        dt_above_baseline   = 1 if (dt_ms > self.q_hi_ms) else 0
        dt_in_pub_baseline_flag = 0
        dt_above_pub_baseline   = 0
        dt_below_pub_baseline   = 0

        f_dict = {
            'time_delta': float(dt),
            'time_delta_zscore': float(time_delta_zscore),
            'sqNum': int(sqNum), 'stNum': int(stNum),
            'sqNum_diff': int(sq_diff), 'stNum_diff': int(st_diff),
            'sqNum_diff_abs': int(sq_diff_abs), 'stNum_diff_abs': int(st_diff_abs),
            'sq_backwards_flag': int(sq_backwards_flag),
            'sq_jump_gt1_flag': int(sq_jump_gt1_flag),
            'sq_jump_gt1_abs_flag': int(sq_jump_gt1_abs_flag),
            'sq_backwards_mag': int(sq_backwards_mag),
            'sq_jump_mag': int(sq_jump_mag),
            'st_change_flag': int(st_change_flag),
            'st_change_with_cmd_flag': int(st_change_with_cmd_flag),
            'st_change_without_cmd_flag': int(st_change_without_cmd_flag),
            'sqNum_rolling_mean': float(sq_mean),
            'sqNum_rolling_std': float(sq_std),
            'sqNum_rolling_median': float(sq_med),
            'sqNum_deviation': float(sq_dev),
            'stNum_rolling_mean': float(st_mean),
            'stNum_rolling_std': float(st_std),
            'stNum_rolling_median': float(st_med),
            'stNum_deviation': float(st_dev),
            'sq_frac_pos1': float(sq_frac_pos1),
            'sq_frac_gt1': float(sq_frac_gt1),
            'sq_frac_backwards': float(sq_frac_backwards),
            'st_change_rate': float(st_change_rate),
            'sqNum_consistency': float(sqNum_consistency),
            'stNum_consistency': float(stNum_consistency),
            'unique_seq_patterns': float(unique_seq_patterns),
            'unique_state_patterns': float(unique_state_patterns),
            'sq_circ_diff': int(sq_circ_diff),
            'sq_wrap_flag': int(sq_wrap_flag),
            'sq_incons_flag': int(sq_incons_flag),
            'sq_incons_count_w100': int(sq_incons_count_w100),
            'sq_backwards_count_w100': int(sq_backwards_count_w100),
            'sq_jump_abs_count_w100': int(sq_jump_abs_count_w100),
            'sq_frac_pos1_w100': float(sq_frac_pos1_w100),
            'sq_residual_abs_sum_w100': float(sq_residual_abs_sum_w100),
            'sq_circ_diff_std_w100': float(sq_circ_diff_std_w100),
            'st_injected_count_w100': int(st_injected_count_w100),
            'st_change_count_w100': int(st_change_count_w100),
            'st_change_rate_w100': float(st_change_rate_w100),
            'dt_in_baseline_flag': int(dt_in_baseline_flag),
            'dt_below_baseline': int(dt_below_baseline),
            'dt_above_baseline': int(dt_above_baseline),
            'dt_in_pub_baseline_flag': int(dt_in_pub_baseline_flag),
            'dt_above_pub_baseline': int(dt_above_pub_baseline),
            'dt_below_pub_baseline': int(dt_below_pub_baseline),
        }

        return f_dict

# =============================================================================
#                         Countermeasure (sender) - Copied from original
# =============================================================================

class CountermeasureSender:
    def __init__(self, iface: str, src_mac: str, dst_mac: str = "01:0c:cd:01:00:03", dry_run: bool = False):
        self.iface = iface
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.dry = dry_run
        self.sq_counter = defaultdict(lambda: 0)

    def send(self, fields: dict):
        if self.dry:
            print("[CM] dry-run: would send corrective GOOSE")
            return
        if any(x is None for x in (Ether, encoder, IECGoosePDU, AllData, Data, GOOSE, tag, sendp)):
            print("[CM] dependencies missing; cannot send frame.")
            return

        gocb   = fields.get("gocbRef", "")
        datSet = fields.get("datSet", "")
        goID   = fields.get("goID", "")
        confRev = int(fields.get("confRev", 0))
        tal = int(fields.get("timeAllowedtoLive", 1000))
        appid = int(fields.get("appid", 0x0002))

        new_st = int(fields.get("stNum", 0)) + 1
        sq     = self.sq_counter[gocb]
        self.sq_counter[gocb] += 1

        now = datetime.utcnow()
        epoch = datetime(1970, 1, 1)
        secs = int((now - epoch).total_seconds())
        nanos = int(now.microsecond * 1000)
        ts8 = secs.to_bytes(4, "big") + nanos.to_bytes(4, "big")

        g = IECGoosePDU().subtype(implicitTag=tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1))
        g.setComponentByName('gocbRef', gocb)
        g.setComponentByName('timeAllowedtoLive', tal)
        g.setComponentByName('datSet', datSet)
        if goID:
            g.setComponentByName('goID', goID)
        g.setComponentByName('t', ts8)
        g.setComponentByName('stNum', new_st)
        g.setComponentByName('sqNum', sq)
        g.setComponentByName('simulation', False)
        g.setComponentByName('confRev', confRev)
        g.setComponentByName('ndsCom', False)

        d = AllData().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 11))
        d1 = Data(); d1.setComponentByName('boolean', True)
        d2 = Data(); d2.setComponentByName('bit-string', "'0'B")
        d.setComponentByPosition(0, d1)
        d.setComponentByPosition(1, d2)
        g.setComponentByName('allData', d)
        g.setComponentByName('numDatSetEntries', 2)

        eth = Ether(src=self.src_mac, dst=self.dst_mac, type=0x88B8)
        pkt = eth / GOOSE(appid=appid) / encoder.encode(g)

        print(f"[CM] send stNum={new_st} sqNum={sq} gocbRef={gocb} datSet={datSet}")
        sendp(pkt, iface=self.iface, count=1, verbose=False)

@dataclass
class AttackEvent:
    """Represents a detected attack event with full context"""
    # All fields without defaults must come first
    event_id: int
    publisher_id: str
    detection_time: datetime
    packet_time: datetime
    detection_latency_ms: float
    confidence: float
    attack_type: str
    explanation: str
    packet_details: Dict
    feature_snapshot: Dict
    # Fields with defaults come last
    timeline: List = field(default_factory=list)  # Recent packet history
    
class AlarmEmitter:
    """Emit structured alarms to json/jsonl/stdout, syslog, CEF, or OpenTelemetry-style JSON."""

    def __init__(self, output_format: str = "none", output_dest: Optional[str] = None,
                 syslog_facility: Optional[str] = None, syslog_level: Optional[str] = None):
        self.format = (output_format or "none").lower()
        self.dest = output_dest
        self._logger = None
        self._stream = None
        self._file = None  # file handle if writing to a file
        self._syslog_via_cef = False  # CEF over syslog (udp/tcp)

        # New: defaults for syslog facility/level
        self._facility_name = (syslog_facility or "user").lower()
        self._syslog_level = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL,
        }.get((syslog_level or "info").lower(), logging.INFO)

        if self.format == "none":
            return

        # Routing for destinations
        if self.format == "syslog":
            self._init_syslog(self.dest)
        elif self.format in ("json", "jsonl", "otel", "cef"):
            # CEF may optionally go via syslog when dest uses udp:// or tcp://
            proto_host = self._parse_network_dest(self.dest) if self.dest else None
            if self.format == "cef" and proto_host:
                self._init_syslog(self.dest)
                self._syslog_via_cef = True
            else:
                self._init_stream(self.dest)
        else:
            # Unknown format -> disable
            self.format = "none"

    def _looks_like_windows_path(self, dest: str) -> bool:
        if not dest:
            return False
        drive, _ = os.path.splitdrive(dest)
        return bool(drive)  # e.g., "C:" means it's a path

    def _parse_network_dest(self, dest: Optional[str]):
        if not dest:
            return None
        d = dest.strip()
        if self._looks_like_windows_path(d):
            return None
        # udp://host:port or tcp://host:port
        if d.lower().startswith("udp://") or d.lower().startswith("tcp://"):
            scheme, rest = d.split("://", 1)
            if ":" not in rest:
                raise ValueError("Network destination must be host:port")
            host, port = rest.rsplit(":", 1)
            return (scheme.lower(), host, int(port))
        # host:port (treat as UDP)
        if ":" in d and not os.path.exists(d):
            host, port = d.rsplit(":", 1)
            try:
                return ("udp", host, int(port))
            except ValueError:
                return None
        return None

    def _init_syslog(self, dest: Optional[str]):
        self._logger = logging.getLogger("goose_idrs.alarm")
        self._logger.setLevel(logging.DEBUG)  # let handler/emit decide severity
        self._logger.propagate = False

        # Resolve facility
        try:
            facility = SysLogHandler.facility_names.get(self._facility_name, SysLogHandler.LOG_USER)
        except Exception:
            facility = SysLogHandler.LOG_USER

        proto_host = self._parse_network_dest(dest)
        if proto_host:
            scheme, host, port = proto_host
            socktype = socket.SOCK_STREAM if scheme == "tcp" else socket.SOCK_DGRAM
            handler = SysLogHandler(address=(host, port), socktype=socktype, facility=facility)
        else:
            handler = SysLogHandler(address=("127.0.0.1", 514), socktype=socket.SOCK_DGRAM, facility=facility)

        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def _init_stream(self, dest: Optional[str]):
        # "-" or None -> stdout; else open file (append, UTF-8)
        if dest in (None, "-", ""):
            self._stream = sys.stdout
            return
        # If the dest looks like network, do not treat as file here.
        if self._parse_network_dest(dest):
            raise ValueError(f"Network destination not supported for format '{self.format}'. Use syslog or CEF with udp:// or tcp://.")
        # Ensure parent directory exists
        os.makedirs(os.path.dirname(os.path.abspath(dest)) or ".", exist_ok=True)
        self._file = open(dest, "a", encoding="utf-8", buffering=1)
        self._stream = self._file

    def close(self):
        if self._logger:
            for h in list(self._logger.handlers):
                try:
                    h.close()
                except Exception:
                    pass
                self._logger.removeHandler(h)
            self._logger = None
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None
        self._stream = None

    def _now_iso(self):
        return datetime.now(timezone.utc).isoformat()

    def _to_cef(self, event: dict) -> str:
        # Minimal CEF mapping; escape = and | in text fields
        def esc(s: str) -> str:
            return str(s).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")
        sev_map = {
            "DEBUG": 1, "INFO": 3, "NOTICE": 4, "WARNING": 6,
            "ERROR": 8, "CRITICAL": 9, "ALERT": 10, "EMERGENCY": 10, "ATTACK": 10
        }
        severity = sev_map.get(str(event.get("severity_text", "INFO")).upper(), 5)
        body = event.get("body", "Attack detected")
        # Common extensions (best-effort)
        ext = {
            "rt": event.get("ts") or self._now_iso(),
            "msg": event.get("explanation") or body,
            "cat": event.get("category") or "intrusion",
            "cs1Label": "probability",
            "cs1": event.get("probability"),
            "cs2Label": "goID",
            "cs2": event.get("goID"),
            "cs3Label": "stNum",
            "cs3": event.get("stNum"),
            "cs4Label": "sqNum",
            "cs4": event.get("sqNum"),
            "src": event.get("src"),
            "dst": event.get("dst"),
            "suser": event.get("publisher"),
            "deviceSeverity": severity,
        }
        ext_str = " ".join(f"{k}={esc(v)}" for k, v in ext.items() if v is not None)
        return f"CEF:0|GooseIDS|Detector|1.0|attack|Goose Attack|{severity}|{ext_str}"

    def _to_otel(self, event: dict) -> str:
        record = {
            "ts": event.get("ts") or self._now_iso(),
            "severity_text": event.get("severity_text", "ATTACK"),
            "body": event.get("body", "Attack detected"),
            "attributes": {k: v for k, v in event.items() if k not in ("ts", "severity_text", "body")}
        }
        return json.dumps(record, ensure_ascii=False)

    def emit(self, event):
        if self.format == "none":
            return

        # Allow dataclass or dict
        if is_dataclass(event):
            event = asdict(event)
        elif not isinstance(event, dict):
            # Best effort: convert to string body
            event = {"body": str(event)}

        event = dict(event or {})
        event.setdefault("ts", self._now_iso())
        event.setdefault("severity_text", "ATTACK")

        try:
            if self.format in ("json", "jsonl"):
                line = json.dumps(event, ensure_ascii=False)
                self._stream.write(line + "\n")
                self._stream.flush()
            elif self.format == "syslog":
                msg = event.get("body") or event.get("explanation") or "Attack detected"
                self._logger.log(self._syslog_level, msg)
            elif self.format == "cef":
                line = self._to_cef(event)
                if self._syslog_via_cef and self._logger:
                    self._logger.log(self._syslog_level, line)
                else:
                    self._stream.write(line + "\n")
                    self._stream.flush()
            elif self.format == "otel":
                line = self._to_otel(event)
                self._stream.write(line + "\n")
                self._stream.flush()
        except Exception:
            logging.getLogger("goose_idrs.alarm").exception("Failed to emit alarm")

class RealTimeXAI:
    """Provides real-time explainability for attack predictions"""
    
    def __init__(self, feature_names: List[str]):
        self.feature_names = feature_names
        self.attack_patterns = {
            'sequence_manipulation': ['sq_backwards_flag', 'sq_jump_gt1_flag', 'sq_jump_mag'],
            'state_injection': ['st_change_without_cmd_flag', 'st_injected_count_w100'],
            'timing_anomaly': ['dt_above_baseline', 'dt_below_baseline', 'time_delta_zscore'],
            'consistency_violation': ['sqNum_consistency', 'stNum_consistency', 'sq_incons_flag'],
            'protocol_violation': ['sq_wrap_flag', 'sq_circ_diff', 'unique_seq_patterns']
        }
    
    def explain_prediction(self, features: np.ndarray, probability: float, 
                          packet_info: Dict) -> Tuple[str, str]:
        """Generate human-readable explanation for the prediction"""
        feature_dict = dict(zip(self.feature_names, features.flatten()))
        
        # Identify primary attack indicators
        active_patterns = []
        explanations = []
        
        for pattern_name, pattern_features in self.attack_patterns.items():
            pattern_score = sum(feature_dict.get(f, 0) for f in pattern_features if f in feature_dict)
            if pattern_score > 0:
                active_patterns.append(pattern_name)
                
        # Generate specific explanations
        if feature_dict.get('sq_backwards_flag', 0) > 0:
            explanations.append(f"Sequence number went backwards (sqNum: {packet_info.get('sqNum', 'N/A')})")
            
        if feature_dict.get('sq_jump_gt1_flag', 0) > 0:
            explanations.append(f"Sequence number jumped > 1 (jump magnitude: {feature_dict.get('sq_jump_mag', 0)})")
            
        if feature_dict.get('st_change_without_cmd_flag', 0) > 0:
            explanations.append(f"State changed without command (stNum: {packet_info.get('stNum', 'N/A')})")
            
        if feature_dict.get('time_delta_zscore', 0) > 2:
            explanations.append(f"Unusual timing pattern (delta-t z-score: {feature_dict.get('time_delta_zscore', 0):.2f})")
            
        if feature_dict.get('sqNum_consistency', 0) < 0.5:
            explanations.append(f"Low sequence consistency ({feature_dict.get('sqNum_consistency', 0):.3f})")
        
        # Determine primary attack type
        if 'sequence_manipulation' in active_patterns:
            attack_type = "Sequence Manipulation"
        elif 'state_injection' in active_patterns:
            attack_type = "State Injection"
        elif 'timing_anomaly' in active_patterns:
            attack_type = "Timing Anomaly"
        elif 'consistency_violation' in active_patterns:
            attack_type = "Consistency Violation"
        else:
            attack_type = "Protocol Anomaly"
            
        explanation = "; ".join(explanations) if explanations else "Subtle pattern anomaly detected by ML model"
        
        return attack_type, explanation

class EnhancedGooseIDS:
    """Enhanced IDS with multi-stage detection and real-time XAI"""
    
    def __init__(self, model_pkg: str, iface: str, threshold: float = None, 
                 early_warning_threshold: float = None, src_mac: str = "02:00:00:00:00:01",
                 focus_pub: str = None, goid_exact: str = None, goid_substr: str = None,
                 dry_run: bool = False, debug_feats: bool = False, bpf: str = None,
                 report_dir: str = "attack_reports",
                 output_format: Optional[str] = None,
                 output_dest: Optional[str] = None,
                 syslog_facility: Optional[str] = None,
                 syslog_level: Optional[str] = None,
                 emit_warnings: bool = False):
        
        # Load model package
        if not os.path.exists(model_pkg):
            raise FileNotFoundError(f"Model package not found: {model_pkg}")
        pkg = joblib.load(model_pkg)
        self.model = pkg["lgbm_model"]
        self.final_feat_names = list(pkg["feature_names"])
        self.tuned_thr = float(pkg.get("tuned_threshold", 0.5))
        self.q_lo_ms = float(pkg.get("q_lo_ms", 0.1))
        self.q_hi_ms = float(pkg.get("q_hi_ms", 10_000.0))
        
        # Detection thresholds
        self.threshold = float(threshold) if threshold is not None else self.tuned_thr
        self.early_threshold = float(early_warning_threshold) if early_warning_threshold is not None else (self.threshold * 0.3)
        
        # Network configuration
        self.iface = iface
        self.focus_pub = focus_pub
        self.goid_exact = goid_exact
        self.goid_substr = goid_substr
        self.debug = debug_feats
        self.bpf = bpf or "ether[12:2] = 0x88b8 or (ether[12:2] = 0x8100 and ether[16:2] = 0x88b8)"
        
        # Components
        self.extractor = StreamingFeatureExtractor(self.q_lo_ms, self.q_hi_ms, debug_feats=debug_feats)
        self.sender = CountermeasureSender(iface=iface, src_mac=src_mac, dry_run=dry_run)
        self.xai = RealTimeXAI(self.final_feat_names)
        self.emitter = AlarmEmitter(
            output_format=output_format,
            output_dest=output_dest,
            syslog_facility=syslog_facility,
            syslog_level=syslog_level
        )
        self.emit_warnings = bool(emit_warnings)
        
        # State tracking
        self.attack_events: List[AttackEvent] = []
        self.packet_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self.publisher_states: Dict[str, Dict] = defaultdict(dict)
        self.event_counter = 0
        self.warning_counter: Dict[str, int] = defaultdict(int)  # Track consecutive warnings per publisher
        
        # Reporting
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)
        
        print(f"Enhanced IDS initialized:")
        print(f"  Model features: {len(self.final_feat_names)}")
        print(f"  Main threshold: {self.threshold:.4f}")
        print(f"  Early warning: {self.early_threshold:.4f}")
        print(f"  Delta-t baseline (ms): [{self.q_lo_ms:.1f}, {self.q_hi_ms:.1f}]")
        print(f"  Report directory: {self.report_dir}")
        if output_format:
            print(f"  Alarm output: format={output_format} dest={output_dest or '-'}")
    
    def _pub_matches(self, pub: str) -> bool:
        """Check if publisher matches filters"""
        if not self.focus_pub:
            return True
        if len(self.focus_pub) > 2 and self.focus_pub.startswith("r'") and self.focus_pub.endswith("'"):
            pat = self.focus_pub[2:-1]
            return re.search(pat, pub or "") is not None
        if len(self.focus_pub) > 3 and self.focus_pub.startswith('r"') and self.focus_pub.endswith('"'):
            pat = self.focus_pub[2:-1]
            return re.search(pat, pub or "") is not None
        return (pub == self.focus_pub)
    
    def _goid_matches(self, goid: str) -> bool:
        """Check if goID matches filters"""
        if self.goid_exact and goid != self.goid_exact:
            return False
        if self.goid_substr and (self.goid_substr not in goid):
            return False
        return True
    
    def _vec_from_fdict(self, fdict: Dict) -> np.ndarray:
        """Build feature vector in model's expected order"""
        arr = [float(fdict.get(name, 0.0)) for name in self.final_feat_names]
        return np.array(arr, dtype=float).reshape(1, -1)
    
    def _update_packet_history(self, pub: str, packet_info: Dict, features: Dict, probability: float):
        """Maintain packet history for timeline analysis"""
        entry = {
            'timestamp': datetime.now(timezone.utc),
            'packet_time': packet_info.get('t', 0),
            'sqNum': packet_info.get('sqNum', 0),
            'stNum': packet_info.get('stNum', 0),
            'probability': probability,
            'features': features.copy()
        }
        self.packet_history[pub].append(entry)
    
    def _detect_attack_progression(self, pub: str, current_prob: float) -> Dict:
        """Analyze attack progression patterns"""
        history = list(self.packet_history[pub])
        if len(history) < 5:
            return {'progression': 'insufficient_data'}
        
        recent_probs = [h['probability'] for h in history[-10:]]
        
        # Check for sudden spike
        if current_prob > self.threshold and max(recent_probs[:-1]) < self.early_threshold:
            return {'progression': 'sudden_spike', 'pattern': 'immediate_high_confidence'}
        
        # Check for gradual increase
        if len(recent_probs) >= 5:
            increasing_trend = all(recent_probs[i] <= recent_probs[i+1] for i in range(len(recent_probs)-1))
            if increasing_trend and current_prob > self.threshold:
                return {'progression': 'gradual_increase', 'pattern': 'building_confidence'}
        
        # Check for sustained attack
        high_conf_count = sum(1 for p in recent_probs if p > self.threshold)
        if high_conf_count >= 3:
            return {'progression': 'sustained_attack', 'pattern': 'persistent_threat'}
        
        return {'progression': 'single_event', 'pattern': 'isolated_detection'}
    
    def _generate_attack_report(self, event: AttackEvent) -> str:
        """Generate detailed attack report"""
        report_time = datetime.now(timezone.utc).isoformat()
        report_path = os.path.join(self.report_dir, f"attack_{event.event_id:06d}_{int(time.time())}.txt")
        
        # Get recent timeline
        timeline = list(self.packet_history[event.publisher_id])[-20:]
        
        report_content = f"""
GOOSE ATTACK DETECTION REPORT
========================================
Event ID: {event.event_id}
Detection Time: {event.detection_time.isoformat()}
Publisher: {event.publisher_id}
Attack Type: {event.attack_type}
Confidence: {event.confidence:.4f}

ATTACK DETAILS
--------------
Packet Timestamp: {event.packet_time}
Processing Latency (ms): {event.detection_latency_ms:.3f}
State Number: {event.packet_details.get('stNum', 'N/A')}
Sequence Number: {event.packet_details.get('sqNum', 'N/A')}
goID: {event.packet_details.get('goID', 'N/A')}

EXPLANATION (XAI)
-----------------
{event.explanation}

KEY FEATURES AT DETECTION
-------------------------"""
        
        # Add key feature values
        key_features = [
            'sq_backwards_flag', 'sq_jump_gt1_flag', 'st_change_without_cmd_flag',
            'time_delta_zscore', 'sqNum_consistency', 'stNum_consistency'
        ]
        
        for feat in key_features:
            if feat in event.feature_snapshot:
                report_content += f"\n{feat}: {event.feature_snapshot[feat]}"
        
        report_content += f"""

PACKET TIMELINE (Last 20 packets)
----------------------------------
Time                     | sqNum | stNum | Probability | Status
"""
        
        for entry in timeline:
            status = "ATTACK" if entry['probability'] >= self.threshold else "Normal"
            if entry['probability'] >= self.early_threshold and entry['probability'] < self.threshold:
                status = "Warning"
            
            report_content += f"{entry['timestamp'].strftime('%H:%M:%S.%f')[:-3]} | {entry['sqNum']:5d} | {entry['stNum']:5d} | {entry['probability']:9.4f} | {status}\n"
        
        report_content += f"""
COUNTERMEASURE STATUS
--------------------
Remediation Sent: {'Yes' if not self.sender.dry else 'No (Dry Run)'}
Countermeasure Time: {report_time}

END OF REPORT
========================================
"""
        
        # Write report file
        with open(report_path, 'w') as f:
            f.write(report_content)
        
        return report_path
    
    def handle_packet(self, pkt):
        """Enhanced packet handler with multi-stage detection"""
        wall_now = time.time()
        current_time = datetime.fromtimestamp(wall_now, timezone.utc)
        recv_ts = float(getattr(pkt, "time", wall_now))
        detection_latency_ms = max(0.0, (wall_now - recv_ts) * 1000.0)
        
        # Parse packet
        info = parse_goose_packet(pkt)
        if not info:
            return
            
        pub = info.get("gocbRef", "__global__")
        goid = info.get("goID", "")
        
        # Apply filters
        if not self._pub_matches(pub) or not self._goid_matches(goid):
            return
        
        # Extract timing
        t_s = float(info.get("t", float(getattr(pkt, "time", 0.0))))
        packet_time = datetime.fromtimestamp(t_s, timezone.utc) if t_s > 0 else current_time
        sq = int(info.get("sqNum", 0))
        st = int(info.get("stNum", 0))
        allData = info.get("allData", [])
        
        # Extract features
        fdict = self.extractor.make_features(
            pkt_time_s=t_s,
            publisher_id=pub,
            sqNum=sq,
            stNum=st,
            allData=allData
        )
        
        # Predict
        vec = self._vec_from_fdict(fdict)
        proba = float(self.model.predict(vec, num_iteration=getattr(self.model, "best_iteration", None))[0])
        pred = int(proba >= self.threshold)
        
        # Update history
        self._update_packet_history(pub, info, fdict, proba)
        
        # Status determination
        if proba >= self.threshold:
            status = "ATTACK"
        elif proba >= self.early_threshold:
            status = "WARNING"
        else:
            status = "Normal"
        
        # Enhanced console output
        print(f"[{current_time.strftime('%H:%M:%S.%f')[:-3]}] {status} | "
              f"pub={pub[:30]}{'...' if len(pub) > 30 else ''} | "
              f"goID={goid[:20]}{'...' if len(goid) > 20 else ''} | "
              f"st={st:3d} | sq={sq:5d} | "
              f"prob={proba:.4f} | "
              f"pkt_time={packet_time.strftime('%H:%M:%S.%f')[:-3]} | "
              f"lat_ms={detection_latency_ms:.3f}")
        
        # Attack detection and response
        if pred == 1:
            self.event_counter += 1
            
            # Get XAI explanation
            attack_type, explanation = self.xai.explain_prediction(vec, proba, info)
            
            # Analyze progression
            progression = self._detect_attack_progression(pub, proba)
            
            # Create attack event
            event = AttackEvent(
                event_id=self.event_counter,
                publisher_id=pub,
                detection_time=current_time,
                packet_time=packet_time,
                detection_latency_ms=detection_latency_ms,
                confidence=proba,
                attack_type=attack_type,
                explanation=explanation,
                packet_details=info,
                feature_snapshot=fdict,
                timeline=list(self.packet_history[pub])
            )
            
            self.attack_events.append(event)
            
            # Enhanced attack logging
            print(f"\n{'='*80}")
            print(f"ATTACK DETECTED #{self.event_counter}")
            print(f"{'='*80}")
            print(f"Time: {current_time.isoformat()}")
            print(f"Publisher: {pub}")
            print(f"Attack Type: {attack_type}")
            print(f"Confidence: {proba:.4f}")
            print(f"Progression: {progression.get('progression', 'unknown')}")
            print(f"Explanation: {explanation}")
            print(f"Packet Details: stNum={st}, sqNum={sq}")
            print(f"Packet Time: {packet_time.isoformat()}")
            print(f"Processing Latency (ms): {detection_latency_ms:.3f}")
            
            # Generate detailed report
            report_path = self._generate_attack_report(event)
            print(f"Report saved: {report_path}")
            print(f"{'='*80}\n")

            # Emit structured alarm (if configured)
            try:
                event_data = {
                    "event_id": self.event_counter,
                    "severity_text": "ATTACK",
                    "body": f"ATTACK {attack_type} pub={pub} goID={goid} conf={proba:.4f}",
                    "publisher": pub,
                    "goID": goid,
                    "stNum": st,
                    "sqNum": sq,
                    "probability": proba,
                    "latency_ms": detection_latency_ms,
                    "explanation": explanation,
                    "attack_type": attack_type,
                    "ts": current_time.isoformat(),
                    "report_path": report_path,
                    # category/src/dst optional; include if resolvable in your pipeline
                    "category": "intrusion",
                }
                self.emitter.emit(event_data)
            except Exception as e:
                print(f"[WARN] Failed to emit structured alarm: {e}")
            
            # Send countermeasure
            if not self.sender.dry:
                print(f"[CM] Sending countermeasure for event #{self.event_counter}")
            self.sender.send(info)
        
        # Debug feature output for state changes
        if self.debug and fdict.get("st_change_flag", 0) == 1:
            print(f"\n[DEBUG] State change detected at {current_time.isoformat()}")
            print(f"Features snapshot (top indicators):")
            debug_features = [
                'sq_backwards_flag', 'sq_jump_gt1_flag', 'st_change_without_cmd_flag',
                'time_delta_zscore', 'sqNum_consistency', 'unique_seq_patterns'
            ]
            for feat in debug_features:
                if feat in fdict:
                    print(f"  {feat:28s} = {fdict[feat]}")
            print()
        
        # Emit WARNING as structured alarm when enabled
        # Example context variables often present in the ATTACK block:
        #   status, report_text, pub, goid, st, sq, proba, explanation, attack_type, current_time, report_path
        # Emit WARNING as structured alarm when enabled
        if 'status' in locals() and status == "WARNING" and getattr(self, "emit_warnings", False):
            try:
                warning_msg = (locals().get("report_text")
                               or locals().get("warning_msg")
                               or "Suspicious GOOSE activity")
                event = {
                    "severity_text": "WARNING",
                    "body": warning_msg,
                    "publisher": locals().get("pub"),
                    "goID": locals().get("goid"),
                    "stNum": locals().get("st"),
                    "sqNum": locals().get("sq"),
                    "probability": (locals().get("proba")
                                    or locals().get("early_prob")
                                    or locals().get("prob")),
                    "explanation": locals().get("explanation"),
                    "attack_type": locals().get("attack_type"),
                    "ts": (locals().get("current_time").isoformat()
                           if locals().get("current_time") else None),
                    "report_path": locals().get("report_path"),
                    "category": "suspicious",
                }
                self.emitter.emit(event)
            except Exception:
                logging.getLogger("goose_idrs").exception("Failed to emit structured WARNING alarm")
    
    def run(self):
        """Start the enhanced IDS"""
        if sniff is None:
            raise RuntimeError("Scapy not available; cannot sniff.")
        
        print(f"\n{'='*80}")
        print("Starting Enhanced GOOSE IDSR with Real-time XAI")
        print(f"{'='*80}")
        print("Detection Levels:")
        print(f"  Early Warning: {self.early_threshold:.4f}")
        print(f"  Attack Threshold: {self.threshold:.4f}")
        print("Status: Normal | WARNING | ATTACK")
        print("Press Ctrl+C to stop.")
        print(f"{'='*80}\n")
        
        try:
            sniff(iface=self.iface, filter=self.bpf, prn=self.handle_packet, store=0)
        except KeyboardInterrupt:
            print(f"\n\n{'='*80}")
            print("IDS Stopped by user")
            print(f"{'='*80}")
            print(f"Total attacks detected: {len(self.attack_events)}")
            if self.attack_events:
                print("Attack summary:")
                for event in self.attack_events[-5:]:  # Show last 5
                    print(f"  #{event.event_id}: {event.attack_type} "
                          f"(conf={event.confidence:.3f}) at {event.detection_time.strftime('%H:%M:%S')}")
            print(f"Reports saved in: {os.path.abspath(self.report_dir)}")
            print(f"{'='*80}")
        finally:
            try:
                self.emitter.close()
            except Exception:
                pass

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Enhanced GOOSE IDSR with Real-time XAI")
    ap.add_argument("--model", default=os.path.join("artifacts", "ids_lgbm_model.joblib"),
                    help="Path to joblib model package")
    ap.add_argument("--iface", default=os.environ.get("IDS_IFACE", "I210 LAN2"),
                    help="Network interface")
    ap.add_argument("--thr", type=float, default=None, 
                    help="Main attack threshold (default: from model)")
    ap.add_argument("--early-thr", type=float, default=None,
                    help="Early warning threshold (default: 30%% of main threshold)")
    ap.add_argument("--pub", default=None,
                    help="Publisher filter (exact or regex r'...')")
    ap.add_argument("--goid", default=None, help="Exact goID filter")
    ap.add_argument("--goid-substr", default=None, help="goID substring filter")
    ap.add_argument("--output-format", default=None,
                    choices=["json", "jsonl", "syslog", "cef", "otel", "none"],
                    help="Structured alarm output format")
    ap.add_argument("--output-dest", default=None,
                    help="Destination for alarms. File path or '-' for stdout. For network: udp://host:port, tcp://host:port, or host:port")
    ap.add_argument("--syslog-facility", default=None,
                    help="Syslog facility (e.g., user, local0..local7). Default: user")
    ap.add_argument("--syslog-level", default=None,
                    choices=["debug","info","warning","error","critical"],
                    help="Default syslog severity level. Default: info")
    ap.add_argument("--emit-warnings", action="store_true",
                    help="Also emit structured alarms for WARNING-level events")
    ap.add_argument("--src-mac", default=os.environ.get("IDS_SRC_MAC", "02:00:00:00:00:01"),
                    help="Source MAC for countermeasures")
    ap.add_argument("--dry-run", action="store_true", 
                    help="Don't send countermeasures")
    ap.add_argument("--debug-feats", action="store_true", 
                    help="Print feature snapshots on state changes")
    ap.add_argument("--report-dir", default="attack_reports",
                    help="Directory for attack reports")
    ap.add_argument("--bpf", default="ether[12:2] = 0x88b8 or (ether[12:2] = 0x8100 and ether[16:2] = 0x88b8)",
                    help="Packet capture filter")
    args = ap.parse_args()
    try:
        ids = EnhancedGooseIDS(
            model_pkg=args.model,
            iface=args.iface,
            threshold=args.thr,
            early_warning_threshold=args.early_thr,
            src_mac=args.src_mac,
            focus_pub=args.pub,
            goid_exact=args.goid,
            goid_substr=args.goid_substr,
            dry_run=args.dry_run,
            debug_feats=args.debug_feats,
            bpf=args.bpf,
            report_dir=args.report_dir,
            output_format=args.output_format,
            output_dest=args.output_dest,
            syslog_facility=args.syslog_facility,
            syslog_level=args.syslog_level,
            emit_warnings=args.emit_warnings,
        )
        ids.run()
    except Exception as e:
        print(f"Error starting Enhanced IDS: {e}")

if __name__ == "__main__":
    main()
