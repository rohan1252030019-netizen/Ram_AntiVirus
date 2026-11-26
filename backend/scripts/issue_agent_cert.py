#!/usr/bin/env python3
"""Internal CA management script for Ram Antivirus.

Usage:
    python issue_agent_cert.py --init-ca [--ca-dir ./ca]
    python issue_agent_cert.py --issue --agent-id node-01 [--ca-dir ./ca] [--out-dir ./certs]
    python issue_agent_cert.py --revoke --fingerprint <HEX>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add backend directory to sys.path so app modules are resolvable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.ca import InternalCA


def main():
    parser = argparse.ArgumentParser(description="Ram Antivirus Internal CA Management")
    parser.add_argument("--init-ca", action="store_true", help="Initialize internal Root CA")
    parser.add_argument("--issue", action="store_true", help="Issue client certificate for an agent")
    parser.add_argument("--revoke", action="store_true", help="Revoke certificate by fingerprint")
    parser.add_argument("--agent-id", type=str, help="Agent/Node ID for client certificate")
    parser.add_argument("--fingerprint", type=str, help="Certificate SHA256 fingerprint to revoke")
    parser.add_argument("--ca-dir", type=Path, default=Path("./ca"), help="Directory for CA cert and key")
    parser.add_argument("--out-dir", type=Path, default=Path("./certs"), help="Directory to save issued client certs")
    parser.add_argument("--days", type=int, default=365, help="Validity period in days")

    args = parser.parse_args()
    ca = InternalCA()

    if args.init_ca:
        args.ca_dir.mkdir(parents=True, exist_ok=True)
        cert, key = ca.initialize_ca()
        ca.save_ca(args.ca_dir)
        fp = ca.compute_fingerprint(cert)
        print(f"[+] Root CA created successfully in {args.ca_dir}")
        print(f"    CA Fingerprint: {fp}")
        return

    ca_cert_path = args.ca_dir / "ca.crt"
    ca_key_path = args.ca_dir / "ca.key"

    if args.issue:
        if not args.agent_id:
            print("[-] Error: --agent-id is required to issue a certificate")
            sys.exit(1)

        if not ca_cert_path.exists() or not ca_key_path.exists():
            print(f"[*] Initializing new Root CA in {args.ca_dir} first...")
            args.ca_dir.mkdir(parents=True, exist_ok=True)
            ca.initialize_ca()
            ca.save_ca(args.ca_dir)
        else:
            ca.load_ca(ca_cert_path, ca_key_path)

        cert_pem, key_pem, fp = ca.issue_agent_cert(args.agent_id, days_valid=args.days)
        args.out_dir.mkdir(parents=True, exist_ok=True)

        cert_out = args.out_dir / f"{args.agent_id}.crt"
        key_out = args.out_dir / f"{args.agent_id}.key"
        cert_out.write_bytes(cert_pem)
        key_out.write_bytes(key_pem)

        print(f"[+] Issued certificate for agent '{args.agent_id}':")
        print(f"    Certificate: {cert_out}")
        print(f"    Private Key: {key_out}")
        print(f"    Fingerprint: {fp}")
        return

    if args.revoke:
        if not args.fingerprint:
            print("[-] Error: --fingerprint is required to revoke a certificate")
            sys.exit(1)
        ca.revoke_fingerprint(args.fingerprint)
        print(f"[+] Revoked certificate with fingerprint: {args.fingerprint}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
