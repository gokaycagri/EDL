"""
EDL file generation — writes indicator data to Palo Alto / Fortinet / URL list files.
Uses atomic temp-file-then-rename to prevent serving empty EDLs on error.

IMPORTANT: Each regeneration uses a UUID-based unique temp filename to prevent
race conditions between multiple Gunicorn workers. Each process has its own
_REGEN_LOCK, so fixed-name .tmp files would collide between workers.
"""
import logging
import os
import shutil
import threading
import uuid

from .config_manager import DATA_DIR
from .db_manager import get_all_indicators_iter, get_api_blacklist_items
from .utils import is_rfc1918_private_ipv4_indicator

logger = logging.getLogger(__name__)

_REGEN_LOCK = threading.Lock()


def regenerate_edl_files():
    """
    Regenerates EDL files using streaming. Writes to temp files first
    to prevent serving empty EDLs on error. Only one instance at a time per worker.
    """
    if not _REGEN_LOCK.acquire(blocking=False):
        logger.info("EDL regeneration already in progress, skipping call.")
        return False, "Regeneration already in progress."

    # Unique run ID avoids cross-worker .tmp file collisions
    run_id = uuid.uuid4().hex[:8]

    def _task():
        logger.info("Regenerating EDL files from database (run_id=%s)...", run_id)
        tmp = {}
        try:
            paths = {
                "palo_alto_ip":     os.path.join(DATA_DIR, "palo_alto_ip.txt"),
                "palo_alto_domain": os.path.join(DATA_DIR, "palo_alto_domain.txt"),
                "fortinet_ip":      os.path.join(DATA_DIR, "fortinet_ip.txt"),
                "fortinet_domain":  os.path.join(DATA_DIR, "fortinet_domain.txt"),
                "url_list":         os.path.join(DATA_DIR, "url_list.txt"),
            }
            # UUID suffix ensures concurrent workers don't share .tmp files
            tmp = {k: v + f".{run_id}.tmp" for k, v in paths.items()}

            with (
                open(tmp["palo_alto_ip"],     "w") as pa_ip,
                open(tmp["palo_alto_domain"], "w") as pa_dom,
                open(tmp["fortinet_ip"],      "w") as fn_ip,
                open(tmp["fortinet_domain"],  "w") as fn_dom,
                open(tmp["url_list"],         "w") as url_l,
            ):
                count          = 0
                skipped_private = 0
                count_ip       = 0
                count_domain   = 0
                count_url      = 0

                for row in get_all_indicators_iter():
                    ind   = row["indicator"]
                    itype = row["type"]

                    if itype in ("ip", "cidr") and is_rfc1918_private_ipv4_indicator(ind, itype):
                        skipped_private += 1
                        continue

                    if itype in ("ip", "cidr"):
                        pa_ip.write(f"{ind}\n")
                        fn_ip.write(f"{ind}\n")
                        count_ip += 1
                    elif itype == "domain":
                        pa_dom.write(f"{ind}\n")
                        fn_dom.write(f"{ind}\n")
                        count_domain += 1
                    elif itype == "url":
                        url_l.write(f"{ind}\n")
                        count_url += 1

                    count += 1

                # API Blacklist items (manual blocks, FortiDeceptor)
                for item in get_api_blacklist_items():
                    ind   = item["item"]
                    itype = item["type"]

                    if itype in ("ip", "cidr") and is_rfc1918_private_ipv4_indicator(ind, itype):
                        skipped_private += 1
                        continue

                    if itype in ("ip", "cidr"):
                        pa_ip.write(f"{ind}\n")
                        fn_ip.write(f"{ind}\n")
                        count_ip += 1
                    elif itype == "domain":
                        pa_dom.write(f"{ind}\n")
                        fn_dom.write(f"{ind}\n")
                        count_domain += 1

                    count += 1

            # Atomic rename — safe because each worker has its own unique tmp paths
            for key in paths:
                os.replace(tmp[key], paths[key])

            # Legacy compatibility copies
            shutil.copy(paths["palo_alto_ip"], os.path.join(DATA_DIR, "palo_alto_edl.txt"))
            shutil.copy(paths["fortinet_ip"],  os.path.join(DATA_DIR, "fortinet_edl.txt"))

            logger.info(
                "EDL regenerated OK (run=%s) | Total: %s | IP/CIDR: %s | Domain: %s | URL: %s | Skipped-private: %s",
                run_id, count, count_ip, count_domain, count_url, skipped_private,
            )

        except Exception as e:
            logger.error("Error regenerating EDL files (run=%s): %s", run_id, e, exc_info=True)
            for key, tmp_path in tmp.items():
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        finally:
            _REGEN_LOCK.release()

    thread = threading.Thread(target=_task, name=f"EDLRegenThread-{run_id}")
    thread.daemon = True
    thread.start()
    logger.info("Started background EDL regeneration task (run_id=%s).", run_id)
    return True, "Regeneration started in background."
