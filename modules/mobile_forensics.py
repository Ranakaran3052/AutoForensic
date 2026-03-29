"""
mobile_forensics.py  —  AutoForenX Mobile Evidence Module
==========================================================
Parses Android / iOS acquisition sources for:
  • Call logs   (incoming / outgoing / missed / VoIP / duration / timestamps)
  • Messages    (SMS / MMS / iMessage / WhatsApp / Telegram / Signal)
  • Location    (GPS fixes, cell towers, Wi-Fi geolocation, geo-tagged media)
  • App data    (installed, uninstalled, permissions, last-used timestamps)
  • Device IDs  (IMEI, IMSI, ICCID, serial, Android ID, UDID, MAC, build)

Acquisition methods supported (NO brute-force — use lawful access):
  Android : ADB backup  (.ab)  |  physical dump (.img / .bin)  |  extracted tar
  iOS     : iTunes/Finder backup (unencrypted or decrypted)    |  physical dump

Usage
-----
    from mobile_forensics import MobileForensicsModule
    mfm = MobileForensicsModule(case_id="CASE-20240115-0042")
    report = mfm.run(source_path="/evidence/device_backup")
"""

import os
import re
import json
import time
import sqlite3
import hashlib
import tarfile
import zipfile
import struct
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
# TIMESTAMP HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _unix_to_iso(ts: float) -> str:
    """Unix epoch → ISO-8601 UTC string."""
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return str(ts)


def _apple_to_iso(ts: float) -> str:
    """CoreData / Apple timestamp (seconds since 2001-01-01) → ISO-8601 UTC."""
    APPLE_EPOCH_OFFSET = 978307200   # seconds between 1970-01-01 and 2001-01-01
    try:
        return _unix_to_iso(float(ts) + APPLE_EPOCH_OFFSET)
    except Exception:
        return str(ts)


def _ms_to_iso(ts: float) -> str:
    """Millisecond Unix epoch → ISO-8601 UTC."""
    try:
        return _unix_to_iso(float(ts) / 1000)
    except Exception:
        return str(ts)


# ══════════════════════════════════════════════════════════════════════════════
# DEVICE IDENTIFIER PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

DEVICE_ID_PATTERNS = {
    # IMEI: 15 digits (Luhn-valid in real devices; we match the pattern)
    "imei":       re.compile(rb"\b(\d{15})\b"),
    # IMSI: 15 digits starting with MCC (2-3 digits) + MNC (2-3 digits)
    "imsi":       re.compile(rb"\bIMSI[=:\s\"']*(\d{13,15})\b", re.IGNORECASE),
    # ICCID: 18-22 digits, often prefixed
    "iccid":      re.compile(rb"\bICCID[=:\s\"']*(\d{18,22})\b", re.IGNORECASE),
    # Android ID: 16 hex chars
    "android_id": re.compile(rb"\b([0-9a-fA-F]{16})\b"),
    # iOS UDID: 40 hex chars or 25-char hyphenated
    "udid":       re.compile(rb"\b([0-9a-fA-F]{40}|[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\b"),
    # MAC address
    "mac":        re.compile(rb"\b([0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5})\b"),
    # Serial number: alphanumeric 8-20 chars after keyword
    "serial":     re.compile(rb"(?:serial[_\s]?(?:number|no)?|SerialNumber)[=:\s\"']*([A-Z0-9]{8,20})\b", re.IGNORECASE),
    # Build fingerprint (Android)
    "build_fingerprint": re.compile(rb"[a-zA-Z0-9_\.]+/[a-zA-Z0-9_\.]+/[a-zA-Z0-9_:]+:[0-9]+\.[0-9]+[^\s\x00]{0,60}"),
    # Phone number in E.164
    "phone_e164": re.compile(rb"\+\d{7,15}\b"),
}


# ══════════════════════════════════════════════════════════════════════════════
# CALL LOG PATTERNS  (binary / text fallback when no DB available)
# ══════════════════════════════════════════════════════════════════════════════

CALL_TYPE_MAP_ANDROID = {1: "INCOMING", 2: "OUTGOING", 3: "MISSED",
                          4: "VOICEMAIL", 5: "REJECTED", 6: "BLOCKED",
                          7: "ANSWERED_EXTERNALLY"}

CALL_TYPE_MAP_IOS = {1: "INCOMING", 2: "OUTGOING", 3: "MISSED",
                      0: "UNKNOWN"}

VOIP_INDICATORS = re.compile(
    rb"(?:whatsapp|telegram|signal|facetime|skype|viber|zoom|meet|discord"
    rb"|line|wechat|kakaotalk|imo|duo|teams)[\x00-\x20]{0,4}call",
    re.IGNORECASE
)


# ══════════════════════════════════════════════════════════════════════════════
# APP PACKAGE PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

ANDROID_PKG_RE  = re.compile(rb"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}", re.IGNORECASE)
IOS_BUNDLE_RE   = re.compile(rb"com\.[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+")

SUSPICIOUS_APPS = {
    # Stalkerware / spyware
    "com.thetruthspy", "com.hoverwatch", "com.spyzie", "com.ikeymonitor",
    "com.mspy", "com.familytracker", "org.xdispy", "com.spyera",
    # RATs / backdoors
    "com.androrat", "com.ahmyth", "com.droidjack", "com.omnirat",
    # Known malware families
    "com.example.fakegooglemaps", "com.android.chrome.update",
    "com.security.antivirus.fake",
}


# ══════════════════════════════════════════════════════════════════════════════
# LOCATION PATTERNS  (binary fallback)
# ══════════════════════════════════════════════════════════════════════════════

# Decimal degrees lat/lon embedded as text
LAT_LON_TEXT = re.compile(
    rb"(-?[1-8]?\d(?:\.\d{4,10}))[,\s;|]{1,4}(-?1?[0-8]?\d(?:\.\d{4,10}))"
)

# EXIF GPS IFD tag markers (0x8825) followed by lat/lon rational values
EXIF_GPS_TAG = re.compile(rb"\x25\x88[\x00-\xFF]{0,6}\x02\x00\x00\x00")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN MODULE CLASS
# ══════════════════════════════════════════════════════════════════════════════

class MobileForensicsModule:
    """
    Forensic extraction engine for Android and iOS acquisition sources.

    Parameters
    ----------
    case_id   : Existing case ID from ram_analyzer (CASE-YYYYMMDD-XXXX)
    platform  : 'android' | 'ios' | 'auto'  (default: auto-detect)
    output_dir: Where to write per-section JSON reports
    """

    def __init__(self, case_id: str,
                 platform: str = "auto",
                 output_dir: str = "mobile_reports"):
        self.case_id    = case_id
        self.platform   = platform.lower()
        self.output_dir = output_dir
        self._work_dir  = None          # temp extraction dir
        self.findings   = {
            "case_id":          case_id,
            "platform":         None,
            "acquisition_hash": None,
            "device_ids":       {},
            "call_logs":        [],
            "messages":         [],
            "location_data":    [],
            "apps_installed":   [],
            "apps_uninstalled": [],
            "app_permissions":  {},
            "voip_artifacts":   [],
            "raw_scan_hits":    {},
        }

    # ──────────────────────────────────────────────────────────────────────────
    # PUBLIC ENTRY POINT
    # ──────────────────────────────────────────────────────────────────────────

    def run(self, source_path: str) -> dict:
        """
        Main entry point.  source_path may be:
          - A directory (extracted backup / ADB tar contents)
          - A .ab file   (Android Backup)
          - A .zip file  (iTunes backup or exported package)
          - A raw binary dump (.img / .bin)
        Returns the full findings dict and writes JSON to output_dir.
        """
        print(f"\n{'='*60}")
        print(f"  AutoForenX  —  Mobile Forensics Module")
        print(f"  Case   : {self.case_id}")
        print(f"  Source : {source_path}")
        print(f"{'='*60}\n")

        if not os.path.exists(source_path):
            print(f"[-] Source not found: {source_path}")
            return self.findings

        # Integrity hash of the acquisition source
        self.findings["acquisition_hash"] = self._hash_source(source_path)
        print(f"[+] Acquisition SHA-256: {self.findings['acquisition_hash']}")

        # Extract archive if needed → work directory
        self._work_dir = self._prepare_work_dir(source_path)

        # Auto-detect platform
        if self.platform == "auto":
            self.platform = self._detect_platform(self._work_dir)
        self.findings["platform"] = self.platform
        print(f"[+] Platform detected : {self.platform.upper()}\n")

        # Run all extraction sub-modules
        self._extract_device_ids()
        self._extract_call_logs()
        self._extract_messages()
        self._extract_location()
        self._extract_app_data()
        self._binary_scan_fallback(source_path)

        # Persist findings
        os.makedirs(self.output_dir, exist_ok=True)
        self._save_report()

        # Cleanup temp dir (not the original evidence)
        if self._work_dir and self._work_dir != source_path:
            shutil.rmtree(self._work_dir, ignore_errors=True)

        self._print_summary()
        return self.findings

    # ──────────────────────────────────────────────────────────────────────────
    # PREPARATION
    # ──────────────────────────────────────────────────────────────────────────

    def _hash_source(self, path: str) -> str:
        h = hashlib.sha256()
        if os.path.isfile(path):
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        else:
            # Hash directory tree (sorted for determinism)
            for root, _, files in os.walk(path):
                for fname in sorted(files):
                    fp = os.path.join(root, fname)
                    try:
                        with open(fp, "rb") as f:
                            for chunk in iter(lambda: f.read(65536), b""):
                                h.update(chunk)
                    except (PermissionError, OSError):
                        pass
        return h.hexdigest()

    def _prepare_work_dir(self, source_path: str) -> str:
        """Extract archive to temp dir; return dir path for DB access."""
        tmp = tempfile.mkdtemp(prefix="autoforenx_mobile_")

        if os.path.isdir(source_path):
            return source_path                  # already a dir

        ext = Path(source_path).suffix.lower()

        if ext == ".zip":
            print("[+] Extracting ZIP acquisition…")
            with zipfile.ZipFile(source_path, "r") as z:
                z.extractall(tmp)
            return tmp

        if ext in (".tar", ".ab"):
            # Android Backup (.ab) has a 24-byte header before zlib stream
            print("[+] Extracting Android backup…")
            try:
                with open(source_path, "rb") as f:
                    header = f.read(24)
                    if b"ANDROID BACKUP" in header:
                        import zlib
                        compressed = f.read()
                        decompressed = zlib.decompress(compressed)
                        tar_path = os.path.join(tmp, "_ab_extracted.tar")
                        with open(tar_path, "wb") as tf:
                            tf.write(decompressed)
                        with tarfile.open(tar_path) as tar:
                            tar.extractall(tmp)
                    else:
                        with tarfile.open(source_path) as tar:
                            tar.extractall(tmp)
            except Exception as e:
                print(f"[!] Archive extraction warning: {e}")
            return tmp

        # Raw dump or unknown — treat as binary; return tmp (will be scanned separately)
        return tmp

    def _detect_platform(self, work_dir: str) -> str:
        """Heuristic: look for known directory / file markers."""
        markers_android = ["data/data", "data/app", "system/build.prop",
                           "apps/com.android", "calllog.db", "mmssms.db"]
        markers_ios     = ["HomeDomain", "Library/CallHistoryDB",
                           "Library/SMS", "Media/DCIM", "31bb7ba8914766d4"
                           "ba40d6dfb6113c8b614be442"]  # known iOS backup hash prefix

        for root, dirs, files in os.walk(work_dir):
            rel = os.path.relpath(root, work_dir)
            for m in markers_android:
                if m.lower() in (rel + "/" + " ".join(files)).lower():
                    return "android"
            for m in markers_ios:
                if m.lower() in (rel + "/" + " ".join(files)).lower():
                    return "ios"
        return "android"   # default fallback

    # ──────────────────────────────────────────────────────────────────────────
    # DEVICE IDENTIFIERS
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_device_ids(self):
        print("[*] Extracting device identifiers…")
        ids = {}

        # ── Android: build.prop ───────────────────────────────
        build_prop = self._find_file("build.prop")
        if build_prop:
            ids.update(self._parse_build_prop(build_prop))

        # ── iOS: Info.plist / device_info ─────────────────────
        for plist_name in ["Info.plist", "device_info.plist", "Manifest.plist"]:
            plist = self._find_file(plist_name)
            if plist:
                ids.update(self._parse_plist_ids(plist))

        # ── Binary pattern scan across small files ─────────────
        for key, pattern in DEVICE_ID_PATTERNS.items():
            if key in ids:
                continue
            for fpath in self._small_files(max_size=2 * 1024 * 1024):
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    hits = pattern.findall(data)
                    if hits:
                        decoded = [h.decode(errors="ignore") for h in hits]
                        ids.setdefault(key, [])
                        ids[key].extend(decoded)
                        ids[key] = list(dict.fromkeys(ids[key]))[:10]
                except (PermissionError, OSError):
                    pass

        self.findings["device_ids"] = ids
        print(f"    → {len(ids)} identifier type(s) found")

    def _parse_build_prop(self, path: str) -> dict:
        props = {}
        keys_of_interest = {
            "ro.serialno":              "serial",
            "ro.boot.serialno":         "serial",
            "ro.product.model":         "model",
            "ro.product.brand":         "brand",
            "ro.product.manufacturer":  "manufacturer",
            "ro.build.fingerprint":     "build_fingerprint",
            "ro.build.version.release": "android_version",
            "ro.build.id":              "build_id",
            "net.hostname":             "hostname",
            "ro.product.device":        "device_codename",
        }
        try:
            with open(path, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if "=" not in line or line.startswith("#"):
                        continue
                    k, _, v = line.partition("=")
                    if k.strip() in keys_of_interest:
                        props[keys_of_interest[k.strip()]] = v.strip()
        except (PermissionError, OSError):
            pass
        return props

    def _parse_plist_ids(self, path: str) -> dict:
        """Minimal plist key extraction without external libs."""
        props = {}
        try:
            with open(path, "rb") as f:
                data = f.read().decode(errors="ignore")
            pairs = {
                "UniqueDeviceID":   "udid",
                "SerialNumber":     "serial",
                "PhoneNumber":      "phone_number",
                "IMEI":             "imei",
                "MEID":             "meid",
                "ICCID":            "iccid",
                "ProductVersion":   "ios_version",
                "ProductType":      "device_model",
                "DeviceName":       "device_name",
            }
            for xml_key, out_key in pairs.items():
                pat = re.compile(
                    rf"<key>{re.escape(xml_key)}</key>\s*<(?:string|integer)>([^<]+)</(?:string|integer)>",
                    re.IGNORECASE
                )
                m = pat.search(data)
                if m:
                    props[out_key] = m.group(1).strip()
        except (PermissionError, OSError):
            pass
        return props

    # ──────────────────────────────────────────────────────────────────────────
    # CALL LOGS
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_call_logs(self):
        print("[*] Extracting call logs…")
        calls = []

        # ── Android: calllog provider DB ──────────────────────
        for db_name in ["calllog.db", "contacts2.db", "dialer.db"]:
            db = self._find_file(db_name)
            if db:
                calls.extend(self._parse_android_calllog(db))

        # ── iOS: CallHistory.storedata ─────────────────────────
        for db_name in ["CallHistory.storedata", "call_history.db"]:
            db = self._find_file(db_name)
            if db:
                calls.extend(self._parse_ios_calllog(db))

        # ── VoIP artifact scan ────────────────────────────────
        voip = self._scan_voip_artifacts()
        self.findings["voip_artifacts"] = voip

        # Deduplicate by (number, timestamp)
        seen = set()
        unique = []
        for c in calls:
            key = (c.get("number",""), c.get("timestamp",""))
            if key not in seen:
                seen.add(key)
                unique.append(c)

        self.findings["call_logs"] = sorted(unique, key=lambda x: x.get("timestamp",""))
        print(f"    → {len(unique)} call record(s)  |  {len(voip)} VoIP artifact(s)")

    def _parse_android_calllog(self, db_path: str) -> list:
        records = []
        try:
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()

            # Try standard Android call_log table schema
            cur.execute("""
                SELECT
                    number,
                    date,
                    duration,
                    type,
                    geocoded_location,
                    presentation,
                    subscription_id,
                    via_number,
                    features
                FROM calls
                ORDER BY date DESC
            """)
            for row in cur.fetchall():
                call_type = CALL_TYPE_MAP_ANDROID.get(row["type"], f"UNKNOWN({row['type']})")
                records.append({
                    "platform":   "android",
                    "number":     row["number"] or "WITHHELD",
                    "timestamp":  _ms_to_iso(row["date"]),
                    "duration_s": row["duration"],
                    "type":       call_type,
                    "location":   row["geocoded_location"] or "",
                    "via_number": row["via_number"] or "",
                    "voip":       bool(row["features"] and row["features"] & 0x08),
                })
            con.close()
        except sqlite3.Error as e:
            print(f"    [!] Android calllog parse warning ({os.path.basename(db_path)}): {e}")
        return records

    def _parse_ios_calllog(self, db_path: str) -> list:
        records = []
        try:
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()

            # iOS CallHistory Core Data schema
            cur.execute("""
                SELECT
                    ZADDRESS        AS number,
                    ZDATE           AS date,
                    ZDURATION       AS duration,
                    ZORIGINATED     AS originated,
                    ZANSWERED       AS answered,
                    ZSERVICE_PROVIDER AS service,
                    ZISO_COUNTRY_CODE AS country,
                    ZNAME           AS contact_name
                FROM ZCALLRECORD
                ORDER BY ZDATE DESC
            """)
            for row in cur.fetchall():
                if row["originated"]:
                    call_type = "OUTGOING"
                elif row["answered"]:
                    call_type = "INCOMING"
                else:
                    call_type = "MISSED"
                voip = bool(row["service"] and row["service"].lower() not in
                            ("com.apple.mobilephone", ""))
                records.append({
                    "platform":      "ios",
                    "number":        row["number"] or "WITHHELD",
                    "contact_name":  row["contact_name"] or "",
                    "timestamp":     _apple_to_iso(row["date"]),
                    "duration_s":    round(row["duration"], 1) if row["duration"] else 0,
                    "type":          call_type,
                    "voip":          voip,
                    "service":       row["service"] or "cellular",
                    "country_code":  row["country"] or "",
                })
            con.close()
        except sqlite3.Error as e:
            print(f"    [!] iOS calllog parse warning ({os.path.basename(db_path)}): {e}")
        return records

    def _scan_voip_artifacts(self) -> list:
        """Scan all text/binary files for VoIP call evidence strings."""
        hits = []
        for fpath in self._small_files(max_size=5 * 1024 * 1024):
            try:
                with open(fpath, "rb") as f:
                    data = f.read()
                for m in VOIP_INDICATORS.finditer(data):
                    ctx_start = max(0, m.start() - 60)
                    ctx_end   = min(len(data), m.end() + 60)
                    context   = data[ctx_start:ctx_end].decode(errors="ignore").strip()
                    hits.append({
                        "file":    os.path.relpath(fpath, self._work_dir),
                        "match":   m.group(0).decode(errors="ignore"),
                        "context": context,
                    })
            except (PermissionError, OSError):
                pass
        return hits

    # ──────────────────────────────────────────────────────────────────────────
    # MESSAGES
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_messages(self):
        print("[*] Extracting messages…")
        messages = []

        # ── Android SMS/MMS ───────────────────────────────────
        for db_name in ["mmssms.db", "telephony.db", "sms.db"]:
            db = self._find_file(db_name)
            if db:
                messages.extend(self._parse_android_sms(db))

        # ── iOS iMessage / SMS ────────────────────────────────
        ios_sms = self._find_file("sms.db")
        if ios_sms:
            messages.extend(self._parse_ios_sms(ios_sms))

        # ── WhatsApp ──────────────────────────────────────────
        for db_name in ["msgstore.db", "msgstore.db.crypt14",
                        "msgstore.db.crypt15", "ChatStorage.sqlite"]:
            db = self._find_file(db_name)
            if db:
                messages.extend(self._parse_whatsapp(db))

        # ── Telegram ──────────────────────────────────────────
        for db_name in ["cache4.db", "tgnet.data"]:
            db = self._find_file(db_name)
            if db:
                messages.extend(self._parse_telegram(db))

        # ── Signal ────────────────────────────────────────────
        signal_db = self._find_file("signal.db")
        if signal_db:
            messages.extend(self._parse_signal(signal_db))

        self.findings["messages"] = sorted(
            messages, key=lambda x: x.get("timestamp", "")
        )
        print(f"    → {len(messages)} message record(s)")

    def _parse_android_sms(self, db_path: str) -> list:
        records = []
        try:
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("""
                SELECT address, date, type, body, read,
                       service_center, thread_id, locked
                FROM sms
                ORDER BY date DESC
                LIMIT 50000
            """)
            for row in cur.fetchall():
                direction = "OUTGOING" if row["type"] == 2 else "INCOMING"
                records.append({
                    "platform":  "android",
                    "app":       "SMS/MMS",
                    "from_to":   row["address"] or "UNKNOWN",
                    "direction": direction,
                    "timestamp": _ms_to_iso(row["date"]),
                    "body":      row["body"] or "",
                    "read":      bool(row["read"]),
                    "thread_id": row["thread_id"],
                })
            con.close()
        except sqlite3.Error as e:
            print(f"    [!] Android SMS parse warning: {e}")
        return records

    def _parse_ios_sms(self, db_path: str) -> list:
        records = []
        try:
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("""
                SELECT
                    m.rowid,
                    m.text,
                    m.date         AS msg_date,
                    m.is_from_me,
                    m.service,
                    m.handle_id,
                    h.id           AS address,
                    m.is_read,
                    m.cache_has_attachments
                FROM message m
                LEFT JOIN handle h ON m.handle_id = h.rowid
                ORDER BY m.date DESC
                LIMIT 50000
            """)
            for row in cur.fetchall():
                records.append({
                    "platform":    "ios",
                    "app":         row["service"] or "iMessage/SMS",
                    "from_to":     row["address"] or "UNKNOWN",
                    "direction":   "OUTGOING" if row["is_from_me"] else "INCOMING",
                    "timestamp":   _apple_to_iso(row["msg_date"]),
                    "body":        row["text"] or "",
                    "read":        bool(row["is_read"]),
                    "has_attachment": bool(row["cache_has_attachments"]),
                })
            con.close()
        except sqlite3.Error as e:
            print(f"    [!] iOS SMS parse warning: {e}")
        return records

    def _parse_whatsapp(self, db_path: str) -> list:
        records = []
        try:
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            # Android WhatsApp schema
            cur.execute("""
                SELECT
                    m.key_remote_jid AS chat_id,
                    m.key_from_me    AS from_me,
                    m.timestamp,
                    m.data           AS body,
                    m.media_mime_type,
                    m.media_name,
                    m.status,
                    m.starred
                FROM messages m
                ORDER BY m.timestamp DESC
                LIMIT 50000
            """)
            for row in cur.fetchall():
                records.append({
                    "platform":   "android",
                    "app":        "WhatsApp",
                    "from_to":    row["chat_id"] or "UNKNOWN",
                    "direction":  "OUTGOING" if row["from_me"] else "INCOMING",
                    "timestamp":  _ms_to_iso(row["timestamp"]),
                    "body":       row["body"] or "",
                    "media_type": row["media_mime_type"] or "",
                    "media_name": row["media_name"] or "",
                    "starred":    bool(row["starred"]),
                })
            con.close()
        except sqlite3.Error:
            # Try iOS WhatsApp / ChatStorage schema
            try:
                con = sqlite3.connect(db_path)
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                cur.execute("""
                    SELECT
                        ZCHATSESSION        AS chat,
                        ZISFROMME           AS from_me,
                        ZMESSAGEDATE        AS msg_date,
                        ZTEXT               AS body,
                        ZMEDIAITEM          AS has_media
                    FROM ZWAMESSAGE
                    ORDER BY ZMESSAGEDATE DESC
                    LIMIT 50000
                """)
                for row in cur.fetchall():
                    records.append({
                        "platform":  "ios",
                        "app":       "WhatsApp",
                        "from_to":   str(row["chat"] or "UNKNOWN"),
                        "direction": "OUTGOING" if row["from_me"] else "INCOMING",
                        "timestamp": _apple_to_iso(row["msg_date"]),
                        "body":      row["body"] or "",
                        "has_media": bool(row["has_media"]),
                    })
                con.close()
            except sqlite3.Error:
                pass
        return records

    def _parse_telegram(self, db_path: str) -> list:
        records = []
        try:
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("""
                SELECT
                    uid, date, message, out, media_type,
                    from_id, peer_id
                FROM messages_v2
                ORDER BY date DESC
                LIMIT 50000
            """)
            for row in cur.fetchall():
                records.append({
                    "platform":   "android",
                    "app":        "Telegram",
                    "from_to":    str(row["peer_id"] or row["from_id"] or "UNKNOWN"),
                    "direction":  "OUTGOING" if row["out"] else "INCOMING",
                    "timestamp":  _unix_to_iso(row["date"]),
                    "body":       row["message"] or "",
                    "media_type": row["media_type"] or "",
                })
            con.close()
        except sqlite3.Error:
            pass
        return records

    def _parse_signal(self, db_path: str) -> list:
        records = []
        try:
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("""
                SELECT
                    m.date_sent,
                    m.date_received,
                    m.body,
                    m.type,
                    r.e164      AS phone,
                    r.name      AS contact_name,
                    m.has_attachments
                FROM message m
                LEFT JOIN recipient r ON m.to_recipient_id = r._id
                ORDER BY m.date_sent DESC
                LIMIT 50000
            """)
            for row in cur.fetchall():
                # Signal type: outgoing bit is 0x80 in base type
                direction = "OUTGOING" if (row["type"] or 0) & 0x80 else "INCOMING"
                records.append({
                    "platform":      "android",
                    "app":           "Signal",
                    "from_to":       row["phone"] or "UNKNOWN",
                    "contact_name":  row["contact_name"] or "",
                    "direction":     direction,
                    "timestamp":     _ms_to_iso(row["date_sent"]),
                    "body":          row["body"] or "",
                    "has_attachment": bool(row["has_attachments"]),
                })
            con.close()
        except sqlite3.Error:
            pass
        return records

    # ──────────────────────────────────────────────────────────────────────────
    # LOCATION DATA
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_location(self):
        print("[*] Extracting location data…")
        locations = []

        # ── Android: com.google.android.gms location history ──
        for db_name in ["cache.db", "locations.db", "location.db",
                        "LocationHistory.db", "network_location.db"]:
            db = self._find_file(db_name)
            if db:
                locations.extend(self._parse_location_db(db))

        # ── iOS: significant_location.db / Cache.sqlite ────────
        for db_name in ["Cache.sqlite", "significant_location.db",
                        "consolidated.db", "geo_snap.sqlite"]:
            db = self._find_file(db_name)
            if db:
                locations.extend(self._parse_location_db(db, apple_epoch=True))

        # ── EXIF geo-tags in media files ──────────────────────
        locations.extend(self._scan_exif_locations())

        # ── Binary lat/lon text pattern scan ──────────────────
        locations.extend(self._scan_latlon_text())

        # Deduplicate and sort
        seen = set()
        unique = []
        for loc in locations:
            key = (round(loc.get("lat", 0), 5), round(loc.get("lon", 0), 5),
                   loc.get("timestamp", ""))
            if key not in seen:
                seen.add(key)
                unique.append(loc)

        self.findings["location_data"] = sorted(
            unique, key=lambda x: x.get("timestamp", "")
        )
        print(f"    → {len(unique)} location fix(es)")

    def _parse_location_db(self, db_path: str, apple_epoch: bool = False) -> list:
        """Try common location table schemas."""
        records = []
        ts_fn = _apple_to_iso if apple_epoch else _unix_to_iso
        schemas = [
            # (table, lat_col, lon_col, ts_col, acc_col)
            ("location_history",  "latitude",  "longitude",  "timestamp",  "accuracy"),
            ("locations",         "lat",        "lon",        "time",       "accuracy"),
            ("waypoints",         "latitude",  "longitude",  "date",       "horizontalAccuracy"),
            ("ZLOCATION",         "ZLATITUDE", "ZLONGITUDE", "ZTIMESTAMP", "ZHORIZONTALACCURACY"),
            ("wifi_location",     "latitude",  "longitude",  "timestamp",  "accuracy"),
        ]
        try:
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            for (table, lat, lon, ts, acc) in schemas:
                try:
                    cur.execute(f"""
                        SELECT {lat} AS lat, {lon} AS lon,
                               {ts} AS ts, {acc} AS acc
                        FROM {table}
                        ORDER BY {ts} DESC
                        LIMIT 10000
                    """)
                    for row in cur.fetchall():
                        if row["lat"] and row["lon"]:
                            records.append({
                                "source":    os.path.basename(db_path),
                                "lat":       round(float(row["lat"]), 7),
                                "lon":       round(float(row["lon"]), 7),
                                "timestamp": ts_fn(row["ts"]),
                                "accuracy_m": round(float(row["acc"] or 0), 1),
                            })
                except sqlite3.Error:
                    continue
            con.close()
        except sqlite3.Error:
            pass
        return records

    def _scan_exif_locations(self) -> list:
        """Parse EXIF GPS data from JPEG/TIFF files."""
        records = []
        image_exts = {".jpg", ".jpeg", ".tif", ".tiff", ".heic"}
        if not self._work_dir:
            return records
        for root, _, files in os.walk(self._work_dir):
            for fname in files:
                if Path(fname).suffix.lower() not in image_exts:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    lat, lon, ts = self._read_exif_gps(fpath)
                    if lat is not None:
                        records.append({
                            "source":    "EXIF:" + os.path.relpath(fpath, self._work_dir),
                            "lat":       lat,
                            "lon":       lon,
                            "timestamp": ts or "",
                            "accuracy_m": 0,
                        })
                except Exception:
                    pass
        return records

    def _read_exif_gps(self, path: str):
        """Minimal EXIF GPS parser — no external libs needed."""
        with open(path, "rb") as f:
            data = f.read(65536)   # EXIF is always in first 64 KB

        # Find APP1 EXIF marker
        app1 = data.find(b"\xFF\xE1")
        if app1 == -1:
            return None, None, None
        exif_header = data[app1+4:app1+10]
        if b"Exif" not in exif_header:
            return None, None, None

        # Locate GPS IFD tag 0x8825
        gps_tag_pos = data.find(b"\x25\x88")
        if gps_tag_pos == -1:
            gps_tag_pos = data.find(b"\x88\x25")

        # Simplified rational number reader
        def read_rational(buf, offset):
            try:
                num   = struct.unpack_from("<I", buf, offset)[0]
                denom = struct.unpack_from("<I", buf, offset + 4)[0]
                return num / denom if denom else 0
            except Exception:
                return 0

        # Very simplified: just look for lat/lon decimal-degrees-like values
        ll_match = LAT_LON_TEXT.search(data[gps_tag_pos:gps_tag_pos+200])
        if ll_match:
            lat = round(float(ll_match.group(1).decode(errors="ignore")), 7)
            lon = round(float(ll_match.group(2).decode(errors="ignore")), 7)
            return lat, lon, None

        return None, None, None

    def _scan_latlon_text(self) -> list:
        """Pattern scan for embedded lat/lon strings in text/JSON/XML files."""
        records = []
        if not self._work_dir:
            return records
        text_exts = {".json", ".xml", ".txt", ".log", ".plist", ".db", ".sqlite"}
        for fpath in self._small_files(max_size=10 * 1024 * 1024):
            if Path(fpath).suffix.lower() not in text_exts:
                continue
            try:
                with open(fpath, "rb") as f:
                    data = f.read()
                for m in LAT_LON_TEXT.finditer(data):
                    lat = float(m.group(1).decode(errors="ignore"))
                    lon = float(m.group(2).decode(errors="ignore"))
                    if -90 <= lat <= 90 and -180 <= lon <= 180:
                        records.append({
                            "source":     "text_scan:" + os.path.relpath(fpath, self._work_dir),
                            "lat":        round(lat, 7),
                            "lon":        round(lon, 7),
                            "timestamp":  "",
                            "accuracy_m": 0,
                        })
            except (PermissionError, OSError, ValueError):
                pass
        return records

    # ──────────────────────────────────────────────────────────────────────────
    # APP DATA
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_app_data(self):
        print("[*] Extracting app inventory…")
        installed   = []
        uninstalled = []
        permissions = {}

        if self.platform == "android":
            installed, uninstalled, permissions = self._android_apps()
        else:
            installed, uninstalled, permissions = self._ios_apps()

        # Flag suspicious packages
        for app in installed:
            app["suspicious"] = app.get("package", "") in SUSPICIOUS_APPS

        self.findings["apps_installed"]   = installed
        self.findings["apps_uninstalled"] = uninstalled
        self.findings["app_permissions"]  = permissions
        print(f"    → {len(installed)} installed  |  "
              f"{len(uninstalled)} uninstalled  |  "
              f"{len(permissions)} apps with permissions")

    def _android_apps(self):
        """Parse packages.xml and usage stats DBs."""
        installed   = []
        uninstalled = []
        permissions = {}

        # ── packages.xml ───────────────────────────────────────
        pkg_xml = self._find_file("packages.xml")
        if pkg_xml:
            try:
                with open(pkg_xml, "r", errors="ignore") as f:
                    content = f.read()
                # Extract <package> entries
                pkg_re = re.compile(
                    r'<package\s[^>]*name="([^"]+)"[^>]*'
                    r'(?:codePath="([^"]+)")?[^>]*'
                    r'(?:firstInstallTime="([^"]+)")?[^>]*'
                    r'(?:lastUpdateTime="([^"]+)")?',
                    re.IGNORECASE
                )
                for m in pkg_re.finditer(content):
                    installed.append({
                        "package":       m.group(1),
                        "install_path":  m.group(2) or "",
                        "first_install": _ms_to_iso(int(m.group(3), 16)) if m.group(3) else "",
                        "last_update":   _ms_to_iso(int(m.group(4), 16)) if m.group(4) else "",
                        "source":        "packages.xml",
                    })
                # Permissions per package
                perm_re = re.compile(
                    r'<package name="([^"]+)"[^>]*>.*?'
                    r'(<perms>.*?</perms>)',
                    re.DOTALL | re.IGNORECASE
                )
                for m in perm_re.finditer(content):
                    pkg  = m.group(1)
                    pblk = m.group(2)
                    perms = re.findall(r'name="([^"]+)"', pblk)
                    if perms:
                        permissions[pkg] = perms
            except (PermissionError, OSError):
                pass

        # ── usage_stats DB (uninstalled ghost entries) ─────────
        for db_name in ["usage_stats.xml", "usage-events.xml"]:
            ufile = self._find_file(db_name)
            if ufile:
                try:
                    with open(ufile, "r", errors="ignore") as f:
                        content = f.read()
                    # Packages not in installed list that appear in usage
                    used_pkgs = set(re.findall(r'package="([^"]+)"', content))
                    inst_pkgs = {a["package"] for a in installed}
                    for pkg in used_pkgs - inst_pkgs:
                        uninstalled.append({
                            "package": pkg,
                            "source":  db_name,
                            "note":    "Referenced in usage stats but not in packages.xml",
                        })
                except (PermissionError, OSError):
                    pass

        # ── Binary scan for package names as fallback ──────────
        if not installed:
            for fpath in self._small_files(max_size=2 * 1024 * 1024):
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    for m in ANDROID_PKG_RE.findall(data):
                        pkg = m.decode(errors="ignore")
                        if pkg.count(".") >= 2 and len(pkg) > 8:
                            installed.append({"package": pkg, "source": "binary_scan"})
                except (PermissionError, OSError):
                    pass
            # Deduplicate
            seen = set()
            installed = [x for x in installed
                         if not (x["package"] in seen or seen.add(x["package"]))]

        return installed, uninstalled, permissions

    def _ios_apps(self):
        installed   = []
        uninstalled = []
        permissions = {}

        # ── Manifest.plist / iTunesMetadata.plist ─────────────
        manifest = self._find_file("Manifest.plist")
        if manifest:
            try:
                with open(manifest, "rb") as f:
                    data = f.read().decode(errors="ignore")
                # Extract bundle IDs from Manifest
                bundles = re.findall(r"<key>(com\.[a-zA-Z0-9.\-]+)</key>", data)
                for b in bundles:
                    installed.append({"bundle_id": b, "source": "Manifest.plist"})
            except (PermissionError, OSError):
                pass

        # ── Binary scan for iOS bundle IDs ────────────────────
        for fpath in self._small_files(max_size=2 * 1024 * 1024):
            try:
                with open(fpath, "rb") as f:
                    data = f.read()
                for m in IOS_BUNDLE_RE.findall(data):
                    bid = m.decode(errors="ignore")
                    installed.append({"bundle_id": bid, "source": "binary_scan"})
            except (PermissionError, OSError):
                pass

        # Deduplicate
        seen = set()
        deduped = []
        for x in installed:
            k = x.get("bundle_id","") + x.get("package","")
            if k not in seen:
                seen.add(k)
                deduped.append(x)

        return deduped, uninstalled, permissions

    # ──────────────────────────────────────────────────────────────────────────
    # BINARY FALLBACK SCAN  (for raw dumps / unrecognised sources)
    # ──────────────────────────────────────────────────────────────────────────

    def _binary_scan_fallback(self, source_path: str):
        """
        Chunked binary scan of the raw source file (mirrors ram_analyzer logic)
        to catch any artifacts missed by structured parsers.
        """
        if os.path.isdir(source_path):
            return   # Already walked as a directory

        print("[*] Running binary fallback scan on raw source…")

        hit_patterns = {
            "phone_numbers": re.compile(rb"\+\d{7,15}\b"),
            "imei_raw":      re.compile(rb"\b\d{15}\b"),
            "cell_towers":   re.compile(rb"(?:MCC|MNC|LAC|CellID|cellTower)"
                                        rb"[=:\"'\s]{1,5}(\d{1,6})", re.IGNORECASE),
            "wifi_ssid":     re.compile(rb"SSID[=:\"'\s]{1,5}([^\x00\r\n]{1,32})", re.IGNORECASE),
            "bt_mac":        re.compile(rb"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"),
        }

        raw_hits = {k: set() for k in hit_patterns}
        CHUNK    = 1024 * 1024 * 20

        try:
            fsize = os.path.getsize(source_path)
            with open(source_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    for key, pat in hit_patterns.items():
                        for m in pat.findall(chunk):
                            val = m if isinstance(m, bytes) else m
                            raw_hits[key].add(val.decode(errors="ignore"))
        except (PermissionError, OSError) as e:
            print(f"    [!] Binary scan warning: {e}")

        self.findings["raw_scan_hits"] = {k: sorted(list(v))
                                           for k, v in raw_hits.items()}
        total = sum(len(v) for v in raw_hits.values())
        print(f"    → {total} raw hit(s) across {len(hit_patterns)} pattern(s)")

    # ──────────────────────────────────────────────────────────────────────────
    # UTILITIES
    # ──────────────────────────────────────────────────────────────────────────

    def _find_file(self, filename: str) -> Optional[str]:
        """Walk work_dir and return first match (case-insensitive)."""
        fn_lower = filename.lower()
        for root, _, files in os.walk(self._work_dir):
            for f in files:
                if f.lower() == fn_lower:
                    return os.path.join(root, f)
        return None

    def _small_files(self, max_size: int = 5 * 1024 * 1024):
        """Yield paths of files smaller than max_size."""
        if not self._work_dir:
            return
        for root, _, files in os.walk(self._work_dir):
            for fname in files:
                fp = os.path.join(root, fname)
                try:
                    if os.path.getsize(fp) <= max_size:
                        yield fp
                except OSError:
                    pass

    def _save_report(self):
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        out  = os.path.join(self.output_dir,
                            f"{self.case_id}_mobile_{ts}.json")
        with open(out, "w") as jf:
            json.dump(self.findings, jf, indent=4, default=str)
        print(f"\n[+] Mobile report saved: {out}")

    def _print_summary(self):
        f = self.findings
        print(f"\n{'='*60}")
        print(f"  MOBILE FORENSICS SUMMARY  —  {f['case_id']}")
        print(f"{'='*60}")
        print(f"  Platform       : {(f['platform'] or 'unknown').upper()}")
        print(f"  Source hash    : {f['acquisition_hash'][:16]}…")
        print(f"  Device IDs     : {len(f['device_ids'])} type(s) recovered")
        print(f"  Call records   : {len(f['call_logs'])}")
        print(f"  VoIP artifacts : {len(f['voip_artifacts'])}")
        print(f"  Messages       : {len(f['messages'])}")
        print(f"  Location fixes : {len(f['location_data'])}")
        print(f"  Apps installed : {len(f['apps_installed'])}")
        print(f"  Apps removed   : {len(f['apps_uninstalled'])}")
        suspicious = [a for a in f['apps_installed'] if a.get('suspicious')]
        if suspicious:
            print(f"\n  [!] SUSPICIOUS APPS DETECTED ({len(suspicious)}):")
            for a in suspicious:
                print(f"      → {a.get('package') or a.get('bundle_id')}")
        print(f"{'='*60}\n")


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION HELPER  —  attach to existing ram_analyzer pipeline
# ══════════════════════════════════════════════════════════════════════════════

def run_mobile_module(ram_result: dict, mobile_source: str,
                      platform: str = "auto",
                      output_dir: str = "mobile_reports") -> dict:
    """
    Drop-in integration with analyze_ram_dump_ultra().

    Parameters
    ----------
    ram_result    : dict returned by analyze_ram_dump_ultra()
    mobile_source : path to mobile acquisition (dir / .ab / .zip / .img)
    platform      : 'android' | 'ios' | 'auto'
    output_dir    : directory for JSON reports

    Returns
    -------
    Combined dict merging RAM findings with mobile findings.

    Example
    -------
        from ram_analyzer    import analyze_ram_dump_ultra
        from mobile_forensics import run_mobile_module

        ram = analyze_ram_dump_ultra("memory.img", case_name="CASE-20240115-0042")
        combined = run_mobile_module(ram, "/evidence/android_backup.ab")
        print(combined["mobile"]["call_logs"])
    """
    if not ram_result or "case_id" not in ram_result:
        print("[-] run_mobile_module: invalid or missing ram_result dict.")
        return {}

    mfm = MobileForensicsModule(
        case_id    = ram_result["case_id"],
        platform   = platform,
        output_dir = output_dir,
    )
    mobile_findings = mfm.run(mobile_source)

    combined = dict(ram_result)
    combined["mobile"] = mobile_findings
    return combined


# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description="AutoForenX Mobile Forensics Module"
    )
    parser.add_argument("source",      help="Acquisition path (dir / .ab / .zip / .img)")
    parser.add_argument("--case",      default=None,     help="Case ID (auto-generated if omitted)")
    parser.add_argument("--platform",  default="auto",   choices=["auto","android","ios"])
    parser.add_argument("--output",    default="mobile_reports", help="Output directory")
    args = parser.parse_args()

    # Generate or accept case ID
    case_id = args.case
    if not case_id:
        date_str = datetime.now().strftime("%Y%m%d")
        uid      = hashlib.md5(os.urandom(8)).hexdigest()[:4].upper()
        case_id  = f"CASE-{date_str}-{uid}"
        print(f"[!] Auto-generated Case ID: {case_id}")

    mfm = MobileForensicsModule(
        case_id    = case_id,
        platform   = args.platform,
        output_dir = args.output,
    )
    mfm.run(args.source)