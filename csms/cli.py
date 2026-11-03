"""Administrativne naredbe:

  python -m csms.cli create-admin <email> <lozinka>
  python -m csms.cli reset-password <email> <nova-lozinka>   (isključuje i MFA)
"""
import sys

from .db import User, init_db, session_scope
from .security import hash_password


def main(argv):
    if len(argv) != 3 or argv[0] not in ("create-admin", "reset-password"):
        print(__doc__)
        return 1
    cmd, email, pw = argv[0], argv[1].strip().lower(), argv[2]
    if len(pw) < 10:
        print("Lozinka mora imati barem 10 znakova.")
        return 1
    init_db()
    with session_scope() as s:
        u = s.query(User).filter_by(email=email).one_or_none()
        if cmd == "create-admin":
            if u:
                print("Korisnik već postoji.")
                return 1
            s.add(User(email=email, name=email, password_hash=hash_password(pw), is_admin=True))
        else:
            if not u:
                print("Korisnik ne postoji.")
                return 1
            u.password_hash, u.mfa_enabled, u.totp_secret = hash_password(pw), False, None
            u.failed_logins, u.locked_until, u.active = 0, None, True
    print("Gotovo.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
