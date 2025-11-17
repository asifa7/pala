import os
import hashlib
import json
import time
import csv
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
import platform
import logging
from typing import Dict, List, Optional

# Hashing
try:
    import blake3
    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False
    print("Blake3 not available. Install with: pip install blake3")

# Elasticsearch (use 8.x client)
try:
    from elasticsearch import Elasticsearch
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False
    print("Elasticsearch not available. Install with: pip install \"elasticsearch>=8.12.0\"")


class FileSystemMonitor:
    def __init__(
        self,
        base_paths: List[str],
        db_path: str = "file_monitor.db",
        kibana_url: str = "http://localhost:9200",
        index_name: str = "file-monitor1",
        es_username: str = "",
        es_password: str = "",
        es_verify_certs: bool = False,
        es_timeout: int = 60,
    ):
        self.base_paths = base_paths
        self.db_path = db_path
        self.kibana_url = kibana_url
        self.index_name = index_name
        self.es_username = es_username
        self.es_password = es_password
        self.es_verify_certs = es_verify_certs
        self.es_timeout = es_timeout

        self.suspicious_extensions = {
            ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs", ".js", ".jar"
        }

        self.setup_database()
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler("file_monitor.log"), logging.StreamHandler()],
        )
        self.logger = logging.getLogger(__name__)

    def setup_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS file_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE,
                blake3_hash TEXT,
                file_size INTEGER,
                file_extension TEXT,
                last_modified TIMESTAMP,
                last_scanned TIMESTAMP,
                is_duplicate BOOLEAN DEFAULT 0,
                duplicate_group_id TEXT,
                previous_location TEXT,
                is_corrupted BOOLEAN DEFAULT 0,
                is_suspicious BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_timestamp TIMESTAMP,
                files_scanned INTEGER,
                duplicates_found INTEGER,
                corrupted_files INTEGER,
                suspicious_files INTEGER,
                total_size_bytes INTEGER
            )
            """
        )
        conn.commit()
        conn.close()

    def calculate_blake3_hash(self, file_path: str) -> Optional[str]:
        if not BLAKE3_AVAILABLE:
            return self.calculate_sha256_hash(file_path)
        try:
            hasher = blake3.blake3()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            self.logger.error(f"Error hashing file {file_path}: {e}")
            return None

    def calculate_sha256_hash(self, file_path: str) -> Optional[str]:
        try:
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            self.logger.error(f"Error hashing file {file_path}: {e}")
            return None

    def check_file_corruption(self, file_path: str, expected_hash: str = None) -> bool:
        try:
            with open(file_path, "rb") as f:
                f.read(1024)
            if expected_hash:
                current_hash = self.calculate_blake3_hash(file_path)
                return current_hash != expected_hash
            return False
        except Exception as e:
            self.logger.warning(f"File corruption detected: {file_path} - {e}")
            return True

    def check_suspicious_activity(self, file_path: str, file_stats: os.stat_result) -> Dict:
        suspicious_indicators = {"is_suspicious": False, "reasons": []}
        file_ext = Path(file_path).suffix.lower()

        if file_ext in self.suspicious_extensions:
            suspicious_indicators["is_suspicious"] = True
            suspicious_indicators["reasons"].append(f"Suspicious extension: {file_ext}")

        current_time = time.time()
        if current_time - file_stats.st_ctime < 3600:
            suspicious_indicators["reasons"].append("Recently created file")

        if file_stats.st_size > 100 * 1024 * 1024:
            if file_ext in {".txt", ".log", ".cfg"}:
                suspicious_indicators["is_suspicious"] = True
                suspicious_indicators["reasons"].append("Unusually large text file")

        if platform.system() == "Windows":
            system_dirs = [r"C:\Windows", r"C:\Program Files"]
        else:
            system_dirs = ["/usr", "/bin", "/sbin"]

        for sys_dir in system_dirs:
            if file_path.startswith(sys_dir) and Path(file_path).name.startswith("."):
                suspicious_indicators["is_suspicious"] = True
                suspicious_indicators["reasons"].append("Hidden file in system directory")
                break

        return suspicious_indicators

    def scan_directory(self, directory: str) -> List[Dict]:
        file_records = []
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        file_stats = os.stat(file_path)
                        file_ext = Path(file_path).suffix.lower()
                        file_hash = self.calculate_blake3_hash(file_path)
                        if not file_hash:
                            continue
                        is_corrupted = self.check_file_corruption(file_path)
                        suspicious_check = self.check_suspicious_activity(file_path, file_stats)
                        file_record = {
                            "file_path": file_path,
                            "blake3_hash": file_hash,
                            "file_size": file_stats.st_size,
                            "file_extension": file_ext,
                            "last_modified": datetime.fromtimestamp(
                                file_stats.st_mtime, tz=timezone.utc
                            ).isoformat(),
                            "last_scanned": datetime.now(tz=timezone.utc).isoformat(),
                            "is_corrupted": is_corrupted,
                            "is_suspicious": suspicious_check["is_suspicious"],
                            "suspicious_reasons": suspicious_check["reasons"],
                            "folder_depth": len(Path(file_path).parts)
                            - len(Path(directory).parts),
                            "parent_folder": str(Path(file_path).parent),
                        }
                        file_records.append(file_record)
                        if len(file_records) % 1000 == 0:
                            self.logger.info(f"Scanned {len(file_records)} files...")
                    except (OSError, PermissionError) as e:
                        self.logger.warning(f"Cannot access file {file_path}: {e}")
                        continue
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {e}")
        return file_records

    def find_duplicates(self, file_records: List[Dict]) -> Dict[str, List[Dict]]:
        groups = defaultdict(list)
        for r in file_records:
            if r["blake3_hash"]:
                groups[r["blake3_hash"]].append(r)
        dupes = {h: files for h, files in groups.items() if len(files) > 1}
        for h, files in dupes.items():
            for r in files:
                r["is_duplicate"] = True
                r["duplicate_group_id"] = h
                r["duplicate_count"] = len(files)
        return dupes

    def detect_moved_files(self, current_records: List[Dict]) -> List[Dict]:
        moved = []
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT file_path, blake3_hash FROM file_records")
        existing = {row[1]: row[0] for row in cur.fetchall()}
        conn.close()

        for r in current_records:
            h = r["blake3_hash"]
            if h in existing and existing[h] != r["file_path"]:
                moved.append(
                    {
                        "blake3_hash": h,
                        "old_location": existing[h],
                        "new_location": r["file_path"],
                        "moved_at": datetime.now(tz=timezone.utc).isoformat(),
                    }
                )
        return moved

    def update_database(self, file_records: List[Dict], moved_files: List[Dict]):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("DELETE FROM file_records")
        for r in file_records:
            cur.execute(
                """
                INSERT INTO file_records
                (file_path, blake3_hash, file_size, file_extension, last_modified,
                 last_scanned, is_duplicate, duplicate_group_id, is_corrupted, is_suspicious)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    r["file_path"],
                    r["blake3_hash"],
                    r["file_size"],
                    r["file_extension"],
                    r["last_modified"],
                    r["last_scanned"],
                    r.get("is_duplicate", False),
                    r.get("duplicate_group_id"),
                    r["is_corrupted"],
                    r["is_suspicious"],
                ),
            )
        dupes_count = sum(1 for r in file_records if r.get("is_duplicate"))
        corrupted = sum(1 for r in file_records if r["is_corrupted"])
        suspicious = sum(1 for r in file_records if r["is_suspicious"])
        total_size = sum(r["file_size"] for r in file_records)
        cur.execute(
            """
            INSERT INTO scan_history
            (scan_timestamp, files_scanned, duplicates_found, corrupted_files, suspicious_files, total_size_bytes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(tz=timezone.utc).isoformat(),
                len(file_records),
                dupes_count,
                corrupted,
                suspicious,
                total_size,
            ),
        )
        conn.commit()
        conn.close()

    def _connect_es(self) -> Optional[Elasticsearch]:
        if not ELASTICSEARCH_AVAILABLE:
            return None

        # Support http(s)://host:port string or default localhost
        url = self.kibana_url
        try:
            if url.startswith("http"):
                es = Elasticsearch(
                    url,
                    basic_auth=(self.es_username, self.es_password)
                    if self.es_username
                    else None,
                    verify_certs=self.es_verify_certs,
                    request_timeout=self.es_timeout,
                    headers={
                        # Compatibility with ES 8 speaking v7 wire format when needed
                        "Accept": "application/vnd.elasticsearch+json; compatible-with=7",
                        "Content-Type": "application/vnd.elasticsearch+json; compatible-with=7",
                    },
                )
            else:
                es = Elasticsearch(
                    [{"host": "localhost", "port": 9200, "scheme": "http"}],
                    request_timeout=self.es_timeout,
                    verify_certs=self.es_verify_certs,
                )
            # Warmup/ping
            es.info()
            # Ensure index exists
            try:
                if not es.indices.exists(index=self.index_name):
                    es.indices.create(index=self.index_name)
            except Exception:
                pass
            return es
        except Exception as e:
            self.logger.warning(f"Elasticsearch not reachable: {e}. Skipping upload.")
            return None

    def _safe_index(self, es: Elasticsearch, doc: dict) -> bool:
        for attempt in range(5):
            try:
                # elasticsearch>=8: use 'document='
                es.index(index=self.index_name, document=doc)
                return True
            except Exception as e:
                self.logger.warning(f"ES index attempt {attempt+1} failed: {e}")
                time.sleep(2 * (attempt + 1))
        self.logger.error("ES indexing failed after retries")
        return False

    def send_to_kibana(self, file_records: List[Dict], moved_files: List[Dict], duplicates: Dict):
        es = self._connect_es()
        if not es:
            return

        batch_size = 200
        sent = 0
        for i in range(0, len(file_records), batch_size):
            batch = file_records[i : i + batch_size]
            for r in batch:
                doc = {"@timestamp": r["last_scanned"], "event_type": "file_scan", **r}
                self._safe_index(es, doc)
                sent += 1
            self.logger.info(f"Sent {sent} documents so far...")

        for m in moved_files:
            doc = {"@timestamp": m["moved_at"], "event_type": "file_moved", **m}
            self._safe_index(es, doc)

        if duplicates:
            summary = {
                "@timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "event_type": "duplicate_summary",
                "duplicate_groups": len(duplicates),
                "total_duplicates": sum(len(files) for files in duplicates.values()),
                "duplicate_details": [
                    {
                        "hash": h,
                        "file_count": len(files),
                        "file_paths": [f["file_path"] for f in files],
                        "total_size": sum(f["file_size"] for f in files),
                    }
                    for h, files in duplicates.items()
                ],
            }
            self._safe_index(es, summary)

        self.logger.info(f"Successfully attempted send of {len(file_records)} records to Kibana")

    def export_to_csv(self, file_records: List[Dict], moved_files: List[Dict], output_path: str = "file_scan_results.csv"):
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_path = f"file_scan_{ts}.csv"
            if file_records:
                with open(csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=list(file_records[0].keys()))
                    writer.writeheader()
                    writer.writerows(file_records)
            if moved_files:
                moved_csv = f"moved_files_{ts}.csv"
                with open(moved_csv, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=list(moved_files[0].keys()))
                    writer.writeheader()
                    writer.writerows(moved_files)
            self.logger.info(f"Exported results to {csv_path}")
        except Exception as e:
            self.logger.error(f"Failed to export to CSV: {e}")

    def run_full_scan(self):
        self.logger.info("Starting full file system scan...")
        start = time.time()
        all_records: List[Dict] = []

        for p in self.base_paths:
            if os.path.exists(p):
                self.logger.info(f"Scanning: {p}")
                all_records.extend(self.scan_directory(p))
            else:
                self.logger.warning(f"Path does not exist: {p}")

        self.logger.info(f"Scanned {len(all_records)} files")
        duplicates = self.find_duplicates(all_records)
        self.logger.info(f"Found {len(duplicates)} duplicate groups")
        moved = self.detect_moved_files(all_records)
        self.logger.info(f"Detected {len(moved)} moved files")

        self.update_database(all_records, moved)
        self.send_to_kibana(all_records, moved, duplicates)
        self.export_to_csv(all_records, moved)

        corrupted = sum(1 for r in all_records if r["is_corrupted"])
        suspicious = sum(1 for r in all_records if r["is_suspicious"])
        elapsed = (time.time() - start) / 60
        print("\n=== SCAN SUMMARY ===")
        print(f"Total files scanned: {len(all_records)}")
        print(f"Duplicate groups found: {len(duplicates)}")
        print(f"Files moved: {len(moved)}")
        print(f"Corrupted files: {corrupted}")
        print(f"Suspicious files: {suspicious}")
        print(f"Total size: {sum(r['file_size'] for r in all_records) / (1024*1024*1024):.2f} GB")
        print(f"Scan time: {elapsed:.2f} minutes")
        return all_records, moved, duplicates


if __name__ == "__main__":
    # RAW STRINGS ON WINDOWS to avoid \p etc.
    if platform.system() == "Windows":
        BASE_PATHS = [
            r"C:\asif pala\kibana-9.1.0-windows-x86_64\kibana-9.1.0\bin",  # <-- update to your real folder
        ]
    else:
        BASE_PATHS = [r"C:\asif pala\kibana-9.1.0-windows-x86_64\kibana-9.1.0\bin"]

    monitor = FileSystemMonitor(
        base_paths=BASE_PATHS,
        db_path="file_monitor.db",
        kibana_url=os.getenv("ES_URL", "http://localhost:9200"),
        index_name=os.getenv("ES_INDEX", "testing1"),
        es_username=os.getenv("ES_USERNAME", "elastic"),
        es_password=os.getenv("ES_PASSWORD", "_3Ixrn+I=N6pu_C1IzjW"),
        es_verify_certs=False,
        es_timeout=60,
    )

    try:
        monitor.run_full_scan()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error during scan: {e}")
