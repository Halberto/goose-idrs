"""
Remediation system for GOOSE intrusion detection and response.

This script combines a network sniffer, a streaming feature extractor
that matches the training schema (44 base features + 6 Δt guard flags),
a trained LightGBM model, and an on-the-wire countermeasure.

Workflow:
  1) Sniff GOOSE (EtherType 0x88B8) frames.
  2) Parse ASN.1 BER (GOOSEPDU) and extract core fields.
  3) Compute *the same* features used in training (WIN=10, LONG=100, SEQ_MOD=256).
  4) Score with LightGBM; when proba >= tuned threshold, transmit a corrective
     GOOSE with incremented stNum (and a fresh sqNum) to override the malicious state.

Notes:
  • Requires Npcap/WinPcap and admin privileges to sniff/send (Windows).
  • Model package path defaults to artifacts/ids_lgbm_model.joblib and is expected
    to contain: lgbm_model, feature_names (50), q_lo_ms, q_hi_ms, tuned_threshold.
  • Interface can be a friendly name (e.g., "I210 LAN2") or an Npcap GUID string
    like "\\Device\\NPF_{GUID}". Use PowerShell: Get-NetAdapter | Select Name, InterfaceDescription
  • Countermeasure frame uses the standard GOOSE multicast destination:
        01:0c:cd:01:00:03
    and a configurable source MAC (default 02:00:00:00:00:01). Adjust if needed.

Safety:
  Use only on networks you own/manage for legitimate testing/defense.
"""

import os
import re
import argparse
from collections import deque, defaultdict
from datetime import datetime

import numpy as np
import joblib

# ---- Third-party (present in your repo/environment) ----
try:
    from scapy.all import sniff, Ether, Raw, sendp
except Exception:
    sniff = None
    Ether = None
    Raw = None
    sendp = None

# ASN.1 helpers for building countermeasure PDUs
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
#                         TLV / GOOSE Parsing (BER)
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
        # constructed/others ignored (extend if needed)
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
        # fallbacks if missing
        "t": fields.get("t", float(getattr(pkt, "time", 0.0))),
    }
    info.update(fields)
    return info

# =============================================================================
#          Streaming Feature Extractor (44 + 6 guards) — MATCH TRAINING
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

        # Δt
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

        # diffs
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

        # histories
        s.sq_hist.append(int(sqNum))
        s.st_hist.append(int(stNum))
        s.sq_diff_hist.append(int(sq_diff))
        s.st_diff_hist.append(int(st_diff))
        s.dt_hist.append(float(dt_ms))
        s.cmd_hist.append(int(cmd))

        # rolling WIN=10
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

        # circular diff + flags
        if len(s.sq_hist) >= 2:
            prev_sq = s.sq_hist[-2]
            sq_circ_diff = int((int(sqNum) - int(prev_sq)) % SEQ_MOD)
        else:
            sq_circ_diff = 0
        sq_wrap_flag = 1 if (sq_circ_diff < abs(sq_diff)) else 0
        sq_incons_flag = 1 if (abs(sq_diff) != 1 or abs(st_diff) > 1) else 0

        s.sq_circ_diff_hist.append(int(sq_circ_diff))
        s.sq_residual_hist.append(abs(int(sqNum) - sq_med))

        # long window W=100
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

        # Δt guards (global) — per-pub guards set to 0 (bounds not in pkg)
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
            # guards:
            'dt_in_baseline_flag': int(dt_in_baseline_flag),
            'dt_below_baseline': int(dt_below_baseline),
            'dt_above_baseline': int(dt_above_baseline),
            'dt_in_pub_baseline_flag': int(dt_in_pub_baseline_flag),
            'dt_above_pub_baseline': int(dt_above_pub_baseline),
            'dt_below_pub_baseline': int(dt_below_pub_baseline),
        }

        return f_dict

# =============================================================================
#                         Countermeasure (sender)
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

        # increment state; reset/advance our own sq counter
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

        # minimal allData: boolean true + tiny bit-string
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

# =============================================================================
#                             IDS main loop
# =============================================================================

class GooseIDS:
    def __init__(self, model_pkg: str, iface: str, threshold: float | None, src_mac: str,
                 focus_pub: str | None = None, goid_exact: str | None = None,
                 goid_substr: str | None = None, dry_run: bool = False,
                 debug_feats: bool = False, bpf: str | None = None):
        if not os.path.exists(model_pkg):
            raise FileNotFoundError(f"Model package not found: {model_pkg}")
        pkg = joblib.load(model_pkg)
        self.model = pkg["lgbm_model"]
        self.final_feat_names = list(pkg["feature_names"])   # expected 50
        self.tuned_thr = float(pkg.get("tuned_threshold", 0.5))
        self.q_lo_ms = float(pkg.get("q_lo_ms", 0.1))
        self.q_hi_ms = float(pkg.get("q_hi_ms", 10_000.0))
        self.thr = float(threshold) if (threshold is not None) else self.tuned_thr

        self.iface = iface
        self.focus_pub = focus_pub  # exact match or regex if startswith r"..."
        self.goid_exact = goid_exact
        self.goid_substr = goid_substr
        self.debug = debug_feats
        self.bpf = bpf or "ether proto 0x88b8 OR (vlan and ether proto 0x88b8)"

        self.extractor = StreamingFeatureExtractor(self.q_lo_ms, self.q_hi_ms, debug_feats=debug_feats)
        self.sender = CountermeasureSender(iface=iface, src_mac=src_mac, dry_run=dry_run)

        print(f"Loaded model with {len(self.final_feat_names)} features; threshold={self.thr:.4f}")
        print(f"Δt baseline (ms): [{self.q_lo_ms:.1f}, {self.q_hi_ms:.1f}]")

        active_filters = []
        if self.focus_pub:   active_filters.append(f"gocbRef={self.focus_pub}")
        if self.goid_exact:  active_filters.append(f"goID={self.goid_exact}")
        if self.goid_substr: active_filters.append(f"goID contains '{self.goid_substr}'")
        if active_filters:
            print("Filter:", " AND ".join(active_filters))

    def _pub_matches(self, pub: str) -> bool:
        if not self.focus_pub:
            return True
        # regex if provided like r"..."
        if len(self.focus_pub) > 2 and self.focus_pub.startswith("r'") and self.focus_pub.endswith("'"):
            pat = self.focus_pub[2:-1]
            return re.search(pat, pub or "") is not None
        if len(self.focus_pub) > 3 and self.focus_pub.startswith('r"') and self.focus_pub.endswith('"'):
            pat = self.focus_pub[2:-1]
            return re.search(pat, pub or "") is not None
        return (pub == self.focus_pub)

    def _goid_matches(self, goid: str) -> bool:
        if self.goid_exact and goid != self.goid_exact:
            return False
        if self.goid_substr and (self.goid_substr not in goid):
            return False
        return True

    def _vec_from_fdict(self, fdict: dict) -> np.ndarray:
        # Build feature vector strictly in the order the model expects
        arr = [float(fdict.get(name, 0.0)) for name in self.final_feat_names]
        return np.array(arr, dtype=float).reshape(1, -1)

    def handle_packet(self, pkt):
        info = parse_goose_packet(pkt)
        if not info:
            return
        pub = info.get("gocbRef", "__global__")
        goid = info.get("goID", "")

        if not self._pub_matches(pub):
            return
        if not self._goid_matches(goid):
            return

        t_s = float(info.get("t", float(getattr(pkt, "time", 0.0))))
        sq = int(info.get("sqNum", 0))
        st = int(info.get("stNum", 0))
        allData = info.get("allData", [])

        fdict = self.extractor.make_features(
            pkt_time_s=t_s,
            publisher_id=pub,
            sqNum=sq,
            stNum=st,
            allData=allData
        )
        vec = self._vec_from_fdict(fdict)
        proba = float(self.model.predict(vec, num_iteration=getattr(self.model, "best_iteration", None))[0])
        pred = int(proba >= self.thr)

        print(f"[IDS] goID={goid}, pub={pub}, stNum={st}, sqNum={sq}, proba={proba:.4f}, pred={pred}")

        if self.debug and fdict.get("st_change_flag", 0) == 1:
            print("[DBG] FEATURES(50) snapshot:")
            for name in self.final_feat_names:
                print(f"    {name:28s} = {fdict.get(name, 0.0)}")

        if pred == 1:
            self.sender.send(info)

    def run(self):
        if sniff is None:
            raise RuntimeError("Scapy not available; cannot sniff.")
        print("Starting GOOSE IDS with countermeasure loop. Press Ctrl+C to stop.")
        sniff(iface=self.iface, filter=self.bpf, prn=self.handle_packet, store=0)

# =============================================================================
#                               CLI
# =============================================================================

def main():
    ap = argparse.ArgumentParser(description="GOOSE IDS + Remediation (LightGBM)")
    ap.add_argument("--model", default=os.path.join("artifacts", "ids_lgbm_model.joblib"),
                    help="Path to joblib model package (default: artifacts/ids_lgbm_model.joblib)")
    ap.add_argument("--iface", default=os.environ.get("IDS_IFACE", "I210 LAN2"),
                    help="Interface name or Npcap GUID path (default from IDS_IFACE env or 'I210 LAN2')")
    ap.add_argument("--thr", type=float, default=None, help="Override threshold (default: tuned in model pkg)")
    ap.add_argument("--pub", default=None,
                    help="Only process this publisher (exact) or regex with r'...'/r\"...\"")
    ap.add_argument("--goid", default=None, help="Exact goID to process (others ignored)")
    ap.add_argument("--goid-substr", default=None, help="Substring filter for goID (case-sensitive)")
    ap.add_argument("--src-mac", default=os.environ.get("IDS_SRC_MAC", "02:00:00:00:00:01"),
                    help="Source MAC for countermeasure (default 02:00:00:00:00:01)")
    ap.add_argument("--dry-run", action="store_true", help="Do everything except actually send countermeasure")
    ap.add_argument("--debug-feats", action="store_true", help="Print feature snapshots on st changes")
    ap.add_argument("--bpf", default="ether proto 0x88b8 OR (vlan and ether proto 0x88b8)",
                    help="pcap filter (default handles VLAN-tagged GOOSE)")
    args = ap.parse_args()

    ids = GooseIDS(
        model_pkg=args.model,
        iface=args.iface,
        threshold=args.thr,
        src_mac=args.src_mac,
        focus_pub=args.pub,
        goid_exact=args.goid,
        goid_substr=args.goid_substr,
        dry_run=args.dry_run,
        debug_feats=args.debug_feats,
        bpf=args.bpf
    )
    try:
        ids.run()
    except KeyboardInterrupt:
        print("\nIDS stopped.")
    except Exception as e:
        print(f"Error starting IDS: {e}")

if __name__ == "__main__":
    main()
