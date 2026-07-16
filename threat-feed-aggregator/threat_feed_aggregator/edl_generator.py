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

import ipaddress

from .config_manager import DATA_DIR
from .db_manager import get_all_indicators_iter, get_api_blacklist_items, get_whitelist
from .utils import is_rfc1918_private_ipv4_indicator, is_whitelisted

logger = logging.getLogger(__name__)

_REGEN_LOCK = threading.Lock()
# Set when regenerate_edl_files() is called while a run is already in progress.
# The running task checks this flag in its finally block and starts a follow-up run,
# ensuring that block list changes made during a concurrent regeneration are never lost.
_REGEN_PENDING = threading.Event()


def regenerate_edl_files():
    """
    Regenerates EDL files using streaming. Writes to temp files first
    to prevent serving empty EDLs on error. Only one instance at a time per worker.

    If called while a regeneration is already running, sets _REGEN_PENDING so that
    the running task will start a follow-up regeneration when it finishes — guaranteeing
    that any DB changes (e.g. new block list entries) committed between the two calls
    are included in the final output.
    """
    if not _REGEN_LOCK.acquire(blocking=False):
        _REGEN_PENDING.set()
        logger.info("EDL regeneration already in progress — follow-up queued.")
        return False, "Regeneration queued."

    _REGEN_PENDING.clear()  # this run will capture the current DB state

    # Unique run ID avoids cross-worker .tmp file collisions
    run_id = uuid.uuid4().hex[:8]

    def _task():
        logger.info("Regenerating EDL files from database (run_id=%s)...", run_id)
        tmp = {}
        try:
            paths = {
                "palo_alto_ip": os.path.join(DATA_DIR, "palo_alto_ip.txt"),
                "palo_alto_domain": os.path.join(DATA_DIR, "palo_alto_domain.txt"),
                "fortinet_ip": os.path.join(DATA_DIR, "fortinet_ip.txt"),
                "fortinet_domain": os.path.join(DATA_DIR, "fortinet_domain.txt"),
                "url_list": os.path.join(DATA_DIR, "url_list.txt"),
            }
            # UUID suffix ensures concurrent workers don't share .tmp files
            tmp = {k: v + f".{run_id}.tmp" for k, v in paths.items()}

            with (
                open(tmp["palo_alto_ip"], "w") as pa_ip,
                open(tmp["palo_alto_domain"], "w") as pa_dom,
                open(tmp["fortinet_ip"], "w") as fn_ip,
                open(tmp["fortinet_domain"], "w") as fn_dom,
                open(tmp["url_list"], "w") as url_l,
            ):
                count = 0
                skipped_private = 0
                skipped_whitelisted = 0
                count_ip = 0
                count_domain = 0
                count_url = 0

                # Load whitelist once — applied to both feed indicators and block list items
                _whitelist_db = get_whitelist()
                _whitelist_items = [w["item"] for w in _whitelist_db]
                _whitelist_nets = []
                for _w in _whitelist_items:
                    if "/" in _w:
                        try:
                            _whitelist_nets.append(ipaddress.ip_network(_w, strict=False))
                        except ValueError:
                            pass

                # Track written values to deduplicate across feed indicators and block list
                seen_ip: set[str] = set()
                seen_domain: set[str] = set()
                seen_url: set[str] = set()

                for row in get_all_indicators_iter():
                    ind = row["indicator"]
                    itype = row["type"]

                    if itype in ("ip", "cidr") and is_rfc1918_private_ipv4_indicator(ind, itype):
                        skipped_private += 1
                        continue

                    if is_whitelisted(ind, _whitelist_items, _whitelist_nets)[0]:
                        skipped_whitelisted += 1
                        continue

                    if itype in ("ip", "cidr"):
                        if ind not in seen_ip:
                            seen_ip.add(ind)
                            pa_ip.write(f"{ind}\n")
                            fn_ip.write(f"{ind}\n")
                            count_ip += 1
                    elif itype == "domain":
                        if ind not in seen_domain:
                            seen_domain.add(ind)
                            pa_dom.write(f"{ind}\n")
                            fn_dom.write(f"{ind}\n")
                            count_domain += 1
                    elif itype == "url":
                        if ind not in seen_url:
                            seen_url.add(ind)
                            url_l.write(f"{ind}\n")
                            count_url += 1

                    count += 1

                # API Blacklist items (manual blocks, FortiDeceptor)
                # Deduplicated against feed indicators via the seen_* sets above.
                for item in get_api_blacklist_items():
                    ind = item["item"]
                    itype = item["type"]
                    # validate_indicator() returns "ip/cidr" for individual IPs/CIDRs;
                    # normalise here so manually-added entries reach the EDL files.
                    is_ip_type = itype in ("ip", "cidr", "ip/cidr")

                    if is_ip_type and is_rfc1918_private_ipv4_indicator(ind, itype):
                        skipped_private += 1
                        continue

                    if is_whitelisted(ind, _whitelist_items, _whitelist_nets)[0]:
                        skipped_whitelisted += 1
                        continue

                    if is_ip_type:
                        if ind not in seen_ip:
                            seen_ip.add(ind)
                            pa_ip.write(f"{ind}\n")
                            fn_ip.write(f"{ind}\n")
                            count_ip += 1
                    elif itype == "domain":
                        if ind not in seen_domain:
                            seen_domain.add(ind)
                            pa_dom.write(f"{ind}\n")
                            fn_dom.write(f"{ind}\n")
                            count_domain += 1

                    count += 1

            # Atomic rename — safe because each worker has its own unique tmp paths
            for key in paths:
                os.replace(tmp[key], paths[key])

            # Legacy compatibility copies
            shutil.copy(paths["palo_alto_ip"], os.path.join(DATA_DIR, "palo_alto_edl.txt"))
            shutil.copy(paths["fortinet_ip"], os.path.join(DATA_DIR, "fortinet_edl.txt"))

            logger.info(
                "EDL regenerated OK (run=%s) | Total: %s | IP/CIDR: %s | Domain: %s | URL: %s | Skipped-private: %s | Skipped-whitelisted: %s",
                run_id,
                count,
                count_ip,
                count_domain,
                count_url,
                skipped_private,
                skipped_whitelisted,
            )

        except Exception as e:
            logger.error("Error regenerating EDL files (run=%s): %s", run_id, e, exc_info=True)
            for tmp_path in tmp.values():
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        finally:
            _REGEN_LOCK.release()
            # If another caller set _REGEN_PENDING while we were running, start a
            # follow-up regeneration now so their DB changes reach the EDL files.
            if _REGEN_PENDING.is_set():
                logger.info("Follow-up EDL regeneration triggered (run=%s).", run_id)
                regenerate_edl_files()

    thread = threading.Thread(target=_task, name=f"EDLRegenThread-{run_id}")
    thread.daemon = True
    thread.start()
    logger.info("Started background EDL regeneration task (run_id=%s).", run_id)
    return True, "Regeneration started in background."
