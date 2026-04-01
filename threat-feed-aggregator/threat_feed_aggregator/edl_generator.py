"""
EDL file generation — writes indicator data to Palo Alto / Fortinet / URL list files.
Uses atomic temp-file-then-rename to prevent serving empty EDLs on error.
"""
import logging
import os
import shutil
import threading

from .config_manager import DATA_DIR
from .db_manager import get_all_indicators_iter, get_api_blacklist_items
from .utils import is_rfc1918_private_ipv4_indicator

logger = logging.getLogger(__name__)

_REGEN_LOCK = threading.Lock()


def regenerate_edl_files():
    """
    Regenerates EDL files using streaming. Writes to temp files first
    to prevent serving empty EDLs on error. Only one instance at a time.
    """
    if not _REGEN_LOCK.acquire(blocking=False):
        logger.info("EDL regeneration already in progress, skipping call.")
        return False, "Regeneration already in progress."

    def _task():
        logger.info("Regenerating EDL files from database using streaming...")
        try:
            paths = {
                "palo_alto_ip": os.path.join(DATA_DIR, "palo_alto_ip.txt"),
                "palo_alto_domain": os.path.join(DATA_DIR, "palo_alto_domain.txt"),
                "fortinet_ip": os.path.join(DATA_DIR, "fortinet_ip.txt"),
                "fortinet_domain": os.path.join(DATA_DIR, "fortinet_domain.txt"),
                "url_list": os.path.join(DATA_DIR, "url_list.txt"),
            }
            tmp = {k: v + ".tmp" for k, v in paths.items()}

            with (
                open(tmp["palo_alto_ip"], "w") as pa_ip,
                open(tmp["palo_alto_domain"], "w") as pa_dom,
                open(tmp["fortinet_ip"], "w") as fn_ip,
                open(tmp["fortinet_domain"], "w") as fn_dom,
                open(tmp["url_list"], "w") as url_l,
            ):
                count = 0
                skipped_private = 0
                for row in get_all_indicators_iter():
                    ind = row["indicator"]
                    itype = row["type"]

                    if itype in ("ip", "cidr") and is_rfc1918_private_ipv4_indicator(ind, itype):
                        skipped_private += 1
                        continue

                    if itype in ("ip", "cidr"):
                        pa_ip.write(f"{ind}\n")
                        fn_ip.write(f"{ind}\n")
                    elif itype == "domain":
                        pa_dom.write(f"{ind}\n")
                        fn_dom.write(f"{ind}\n")
                    elif itype == "url":
                        url_l.write(f"{ind}\n")

                    count += 1

                # API Blacklist items (manual blocks, FortiDeceptor)
                for item in get_api_blacklist_items():
                    ind = item["item"]
                    itype = item["type"]

                    if itype in ("ip", "cidr") and is_rfc1918_private_ipv4_indicator(ind, itype):
                        skipped_private += 1
                        continue

                    if itype in ("ip", "cidr"):
                        pa_ip.write(f"{ind}\n")
                        fn_ip.write(f"{ind}\n")
                    elif itype == "domain":
                        pa_dom.write(f"{ind}\n")
                        fn_dom.write(f"{ind}\n")

            # Atomic rename
            for key in paths:
                os.replace(tmp[key], paths[key])

            # Legacy file compatibility
            shutil.copy(paths["palo_alto_ip"], os.path.join(DATA_DIR, "palo_alto_edl.txt"))
            shutil.copy(paths["fortinet_ip"], os.path.join(DATA_DIR, "fortinet_edl.txt"))

            logger.info(
                "EDL files regenerated successfully. (Processed: %s records, skipped private: %s)",
                count,
                skipped_private,
            )
        except Exception as e:
            logger.error(f"Error regenerating EDL files: {e}")
            for key in tmp:
                try:
                    os.unlink(tmp[key])
                except OSError:
                    pass
        finally:
            _REGEN_LOCK.release()

    thread = threading.Thread(target=_task, name="EDLRegenThread")
    thread.daemon = True
    thread.start()
    logger.info("Started background EDL regeneration task.")
    return True, "Regeneration started in background."
