import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from threat_feed_aggregator.cert_manager import generate_self_signed_cert
from threat_feed_aggregator.database.schema import init_db
from threat_feed_aggregator.repositories.user_repo import set_admin_password

# Configure minimal logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def prestart():
    logger.info("Running pre-start checks...")

    # 1. Initialize Database
    try:
        init_db()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        sys.exit(1)

    # 2. Create/Update Default Admin User
    try:
        admin_pass = os.getenv("ADMIN_PASSWORD", "123456")
        success, msg = set_admin_password(admin_pass)
        if success:
            logger.info(f"Admin User Check: {msg}")
        else:
            logger.error(f"Failed to set admin password: {msg}")
    except Exception as e:
        logger.error(f"Error during admin user setup: {e}")

    # 2.5 Run Migration SQL if exists
    migration_path = os.path.join(os.path.dirname(__file__), "..", "data", "migration.sql")
    if False and os.path.exists(migration_path):
        logger.info(f"Found migration file at {migration_path}. Importing data in batches...")
        # ... (rest of commented out logic)

    # 3. Ensure SSL Certificates Exist
    try:
        # generate_self_signed_cert checks if they exist internally
        cert_path, key_path = generate_self_signed_cert()
        logger.info(f"SSL Certificates verified at {cert_path}")
    except Exception as e:
        logger.error(f"Failed to verify/create certificates: {e}")
        sys.exit(1)


if __name__ == "__main__":
    prestart()
