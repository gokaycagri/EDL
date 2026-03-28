import json
import logging
import sqlite3

try:
    from psycopg2 import IntegrityError as PgIntegrityError
except ImportError:
    PgIntegrityError = type(None)

from werkzeug.security import check_password_hash, generate_password_hash

from ..database.connection import DB_TYPE, db_readonly, db_transaction

logger = logging.getLogger(__name__)

def set_admin_password(password, conn=None):
    with db_transaction(conn) as db:
        try:
            hashed_password = generate_password_hash(password)
            if DB_TYPE == 'postgres':
                db.execute('''
                    INSERT INTO users (username, password_hash) VALUES (%s, %s)
                    ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
                ''', ('admin', hashed_password))
            else:
                db.execute('INSERT OR REPLACE INTO users (username, password_hash) VALUES (?, ?)',
                             ('admin', hashed_password))
            return True, "Admin password set/updated."
        except Exception as e:
            return False, str(e)

def get_admin_password_hash(conn=None):
    with db_readonly() as db:
        cursor = db.execute("SELECT password_hash FROM users WHERE username = 'admin'")
        result = cursor.fetchone()
        return result['password_hash'] if result else None

def check_admin_credentials(password, conn=None):
    stored_hash = get_admin_password_hash(conn)
    if stored_hash and check_password_hash(stored_hash, password):
        return True
    return False

# --- Local User Management (Generic) ---

def get_all_users(conn=None):
    """Returns a list of all local users with their profile names."""
    with db_readonly() as db:
        try:
            cursor = db.execute('''
                SELECT u.username, p.name as profile_name
                FROM users u
                LEFT JOIN admin_profiles p ON u.profile_id = p.id
                ORDER BY u.username ASC
            ''')
            results = [dict(row) for row in cursor.fetchall()]
            return results
        except Exception as e:
            logger.error(f"Error fetching users: {e}")
            return []

def add_local_user(username, password, profile_id=1, conn=None):
    """Adds a new local user."""
    with db_transaction(conn) as db:
        try:
            hashed_password = generate_password_hash(password)
            db.execute('INSERT INTO users (username, password_hash, profile_id) VALUES (?, ?, ?)',
                         (username, hashed_password, profile_id))
            return True, f"User {username} added."
        except (sqlite3.IntegrityError, PgIntegrityError):
            return False, "Username already exists."
        except Exception as e:
            return False, str(e)

def update_local_user_password(username, password, conn=None):
    """Updates password for an existing user."""
    with db_transaction(conn) as db:
        try:
            hashed_password = generate_password_hash(password)
            cursor = db.execute('UPDATE users SET password_hash = ? WHERE username = ?',
                              (hashed_password, username))
            if cursor.rowcount > 0:
                return True, "Password updated."
            else:
                return False, "User not found."
        except Exception as e:
            return False, str(e)

def delete_local_user(username, conn=None):
    """Deletes a local user (prevents deleting 'admin')."""
    if username == 'admin':
        return False, "Cannot delete the default admin account."

    with db_transaction(conn) as db:
        try:
            cursor = db.execute('DELETE FROM users WHERE username = ?', (username,))
            if cursor.rowcount > 0:
                return True, "User deleted."
            else:
                return False, "User not found."
        except Exception as e:
            return False, str(e)

def verify_local_user(username, password, conn=None):
    """Verifies credentials for any local user."""
    with db_readonly() as db:
        cursor = db.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result and check_password_hash(result['password_hash'], password):
            return True
        return False

def local_user_exists(username, conn=None):
    """Checks if a user exists in the local database."""
    with db_readonly() as db:
        cursor = db.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return cursor.fetchone() is not None

# --- MFA Functions ---

def get_user_mfa_secret(username, conn=None):
    """Retrieves the MFA secret for a user."""
    with db_readonly() as db:
        cursor = db.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        return result['mfa_secret'] if result else None

def update_user_mfa_secret(username, secret, conn=None):
    """Updates (enables) or clears (disables) the MFA secret. Handles Upsert for LDAP users."""
    with db_transaction(conn) as db:
        try:
            if DB_TYPE == 'postgres':
                db.execute('''
                    INSERT INTO users (username, password_hash, mfa_secret)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (username) DO UPDATE SET mfa_secret = EXCLUDED.mfa_secret
                ''', (username, 'LDAP_USER', secret))
            else:
                cursor = db.execute("SELECT 1 FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    db.execute('UPDATE users SET mfa_secret = ? WHERE username = ?', (secret, username))
                else:
                    db.execute('INSERT INTO users (username, password_hash, mfa_secret) VALUES (?, ?, ?)',
                                 (username, 'LDAP_USER', secret))
            return True, "MFA updated."
        except Exception as e:
            logger.error(f"Error updating MFA secret for {username}: {e}")
            return False, str(e)

def is_mfa_enabled(username, conn=None):
    """Checks if MFA is enabled for the user."""
    secret = get_user_mfa_secret(username, conn)
    return secret is not None and len(secret) > 0

# --- Admin Profile Management ---

def get_admin_profiles(conn=None):
    with db_readonly() as db:
        cursor = db.execute('SELECT * FROM admin_profiles ORDER BY id ASC')
        return [dict(row) for row in cursor.fetchall()]

def add_admin_profile(name, description, permissions, conn=None):
    with db_transaction(conn) as db:
        try:
            db.execute('INSERT INTO admin_profiles (name, description, permissions) VALUES (?, ?, ?)',
                       (name, description, json.dumps(permissions)))
            return True, "Profile added."
        except (sqlite3.IntegrityError, PgIntegrityError):
            return False, "Profile name already exists."
        except Exception as e:
            return False, str(e)

def delete_admin_profile(profile_id, conn=None):
    if profile_id in (1, 2, 3):
        return False, "Cannot delete default profiles."

    with db_transaction(conn) as db:
        try:
            db.execute('UPDATE users SET profile_id = 3 WHERE profile_id = ?', (profile_id,))
            db.execute('DELETE FROM admin_profiles WHERE id = ?', (profile_id,))
            return True, "Profile deleted."
        except Exception as e:
            return False, str(e)

def update_admin_profile(profile_id, description, permissions, conn=None):
    if profile_id == 1:
        return False, "Cannot modify Super_User permissions."

    with db_transaction(conn) as db:
        try:
            db.execute('UPDATE admin_profiles SET description = ?, permissions = ? WHERE id = ?',
                       (description, json.dumps(permissions), profile_id))
            return True, "Profile updated."
        except Exception as e:
            return False, str(e)

def get_user_permissions(username, conn=None):
    """Retrieves the permissions dict for a specific user."""
    with db_readonly() as db:
        cursor = db.execute('''
            SELECT p.permissions
            FROM users u
            JOIN admin_profiles p ON u.profile_id = p.id
            WHERE u.username = ?
        ''', (username,))
        row = cursor.fetchone()
        if row:
            try:
                return json.loads(row['permissions'])
            except Exception:
                return {}
        return {}

# --- LDAP Group Mappings ---

def get_ldap_group_mappings(conn=None):
    with db_readonly() as db:
        cursor = db.execute('''
            SELECT m.id, m.group_dn, p.name as profile_name
            FROM ldap_group_mappings m
            JOIN admin_profiles p ON m.profile_id = p.id
            ORDER BY m.id ASC
        ''')
        return [dict(row) for row in cursor.fetchall()]

def add_ldap_group_mapping(group_dn, profile_id, conn=None):
    with db_transaction(conn) as db:
        try:
            db.execute('INSERT INTO ldap_group_mappings (group_dn, profile_id) VALUES (?, ?)',
                       (group_dn.strip(), profile_id))
            return True, "Mapping added."
        except (sqlite3.IntegrityError, PgIntegrityError):
            return False, "Group DN already mapped."
        except Exception as e:
            return False, str(e)

def delete_ldap_group_mapping(mapping_id, conn=None):
    with db_transaction(conn) as db:
        try:
            db.execute('DELETE FROM ldap_group_mappings WHERE id = ?', (mapping_id,))
            return True, "Mapping deleted."
        except Exception as e:
            return False, str(e)

def get_profile_by_ldap_groups(user_groups, conn=None):
    """
    Checks user groups against mappings and returns the best profile_id.
    Prioritizes profile_id 1 (Super_User) if multiple groups match.
    """
    with db_readonly() as db:
        try:
            cursor = db.execute('SELECT group_dn, profile_id FROM ldap_group_mappings')
            mappings = cursor.fetchall()

            normalized_user_groups = [g.lower() for g in user_groups]
            matched_profile_ids = [
                mapping['profile_id']
                for mapping in mappings
                if mapping['group_dn'].lower() in normalized_user_groups
            ]

            if not matched_profile_ids:
                return None

            if 1 in matched_profile_ids:
                return 1

            return matched_profile_ids[0]
        except Exception as e:
            logger.error(f"Error checking LDAP group mappings: {e}")

        return None
