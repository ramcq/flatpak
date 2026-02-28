#!/bin/bash
# generate-test-gpg-keys.sh — Generate GPG test keys for flatpak GPG key update tests
#
# This script generates all the test GPG keys needed by test-gpg-update.sh.
# It is run ONCE by a developer and the resulting .gpg files are committed
# to the repository under tests/test-keyring3/.
#
# The generated keys are:
#   primary-a.gpg / primary-a.sec.gpg — Base key for Case A (in-place update) tests
#   primary-a-newsubkey.gpg           — Key A with an additional signing subkey
#   primary-a-extended.gpg            — Key A with expiration extended
#   primary-a-revoked.gpg             — Key A with revocation certificate applied
#   primary-a-revokedsubkey.gpg       — Key A with one subkey revoked
#   primary-b-old.gpg / primary-b-old.sec.gpg — Old trusted primary for Case B
#   primary-b-new.sec.gpg             — New primary B secret key (for signing test commits)
#   primary-b-new-crosssigned.gpg     — New primary cross-signed by old primary
#   primary-b-new-unsigned.gpg        — New primary WITHOUT cross-signature
#   primary-b-new-selfsigned.gpg      — New primary cross-signed only by itself
#   unrelated.gpg                     — Completely unrelated key
#
# Requirements: gpg >= 2.1 (for --quick-* commands)

set -euo pipefail

OUTDIR="$(cd "$(dirname "$0")" && pwd)/test-keyring3"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

export GNUPGHOME="$WORK/gnupg"
mkdir -m 700 "$GNUPGHOME"

# Suppress gpg-agent / pinentry prompts
cat > "$GNUPGHOME/gpg-agent.conf" <<AGENTEOF
allow-loopback-pinentry
AGENTEOF

cat > "$GNUPGHOME/gpg.conf" <<GPGEOF
pinentry-mode loopback
GPGEOF

gpg-connect-agent "reloadagent" /bye 2>/dev/null || true

echo "=== Generating Primary A ==="
gpg --batch --passphrase '' --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign cert
Subkey-Type: RSA
Subkey-Length: 2048
Subkey-Usage: sign
Name-Real: Flatpak Test Key A
Name-Email: test-key-a@flatpak.test
Expire-Date: 2030-01-01
%commit
EOF

FPR_A=$(gpg --list-keys --with-colons 'test-key-a@flatpak.test' | awk -F: '/^fpr/{print $10; exit}')
echo "Primary A fingerprint: $FPR_A"

# Export base key A (public + secret)
gpg --export "$FPR_A" > "$OUTDIR/primary-a.gpg"
gpg --export-secret-keys "$FPR_A" > "$OUTDIR/primary-a.sec.gpg"

# Capture the initial subkey fingerprint for later revocation
SUBKEY_A_FPR=$(gpg --list-keys --with-colons "$FPR_A" | awk -F: '/^fpr/{n++; if(n==2) {print $10; exit}}')
echo "Primary A initial subkey fingerprint: $SUBKEY_A_FPR"

# --- Case A: new subkey ---
echo "=== Adding new subkey to A ==="
gpg --batch --passphrase '' --quick-add-key "$FPR_A" rsa2048 sign 2030-01-01
gpg --export "$FPR_A" > "$OUTDIR/primary-a-newsubkey.gpg"

# Also export secret for signing test commits with the new subkey
gpg --export-secret-keys "$FPR_A" > "$OUTDIR/primary-a-newsubkey.sec.gpg"

# Capture the new subkey fingerprint
NEWSUBKEY_A_FPR=$(gpg --list-keys --with-colons "$FPR_A" | awk -F: '/^fpr/{n++; if(n==3) {print $10; exit}}')
echo "New subkey fingerprint: $NEWSUBKEY_A_FPR"

# --- Case A: extended expiry ---
echo "=== Extending expiry of A ==="
gpg --batch --passphrase '' --quick-set-expire "$FPR_A" 2035-01-01
gpg --export "$FPR_A" > "$OUTDIR/primary-a-extended.gpg"

# --- Case A: revoked subkey ---
echo "=== Revoking initial subkey of A ==="
# We need a fresh copy to revoke just the subkey
# First, let's work in a sub-homedir
SUB_WORK="$WORK/subkey-revoke"
mkdir -m 700 "$SUB_WORK"
GNUPGHOME_SAVE="$GNUPGHOME"
export GNUPGHOME="$SUB_WORK"

cat > "$GNUPGHOME/gpg-agent.conf" <<AGENTEOF
allow-loopback-pinentry
AGENTEOF
cat > "$GNUPGHOME/gpg.conf" <<GPGEOF
pinentry-mode loopback
GPGEOF
gpg-connect-agent "reloadagent" /bye 2>/dev/null || true

# Import A's full key
gpg --batch --passphrase '' --import "$OUTDIR/primary-a-newsubkey.sec.gpg"

# Revoke the initial subkey (key grip approach)
# Get the keygrip of the initial subkey
INITIAL_SUBKEY_GRIP=$(gpg --list-keys --with-colons --with-keygrip "$FPR_A" | awk -F: '
  /^sub/{found=1; next}
  found && /^grp/{print $10; exit}
')
echo "Revoking subkey with grip: $INITIAL_SUBKEY_GRIP"

# Use --edit-key in batch mode to revoke the subkey
# Note: empty line after description text terminates the reason description
gpg --batch --passphrase '' --command-fd 0 --status-fd 2 --edit-key "$FPR_A" <<'EDITEOF'
key 1
revkey
y
0
Revoked for testing

y
save
EDITEOF

gpg --export "$FPR_A" > "$OUTDIR/primary-a-revokedsubkey.gpg"

export GNUPGHOME="$GNUPGHOME_SAVE"

# --- Case A: full key revocation ---
echo "=== Generating revocation for A ==="
REV_WORK="$WORK/revoke"
mkdir -m 700 "$REV_WORK"
export GNUPGHOME="$REV_WORK"

cat > "$GNUPGHOME/gpg-agent.conf" <<AGENTEOF
allow-loopback-pinentry
AGENTEOF
cat > "$GNUPGHOME/gpg.conf" <<GPGEOF
pinentry-mode loopback
GPGEOF
gpg-connect-agent "reloadagent" /bye 2>/dev/null || true

# Import A's key
gpg --batch --passphrase '' --import "$OUTDIR/primary-a.sec.gpg"

# Generate revocation cert using --gen-revoke with --no-tty
gpg --no-tty --passphrase '' --command-fd 0 --gen-revoke --output "$WORK/revoke-a.rev" "$FPR_A" <<'REVEOF'
y
0

y
REVEOF
gpg --batch --import "$WORK/revoke-a.rev"
gpg --batch --import "$WORK/revoke-a.rev"
gpg --export "$FPR_A" > "$OUTDIR/primary-a-revoked.gpg"

export GNUPGHOME="$GNUPGHOME_SAVE"

# ======== Case B keys ========

echo "=== Generating Primary B Old ==="
gpg --batch --passphrase '' --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign cert
Subkey-Type: RSA
Subkey-Length: 2048
Subkey-Usage: sign
Name-Real: Flatpak Test Key B Old
Name-Email: test-key-b-old@flatpak.test
Expire-Date: 2030-01-01
%commit
EOF

FPR_B_OLD=$(gpg --list-keys --with-colons 'test-key-b-old@flatpak.test' | awk -F: '/^fpr/{print $10; exit}')
echo "Primary B-old fingerprint: $FPR_B_OLD"

gpg --export "$FPR_B_OLD" > "$OUTDIR/primary-b-old.gpg"
gpg --export-secret-keys "$FPR_B_OLD" > "$OUTDIR/primary-b-old.sec.gpg"

echo "=== Generating Primary B New ==="
gpg --batch --passphrase '' --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign cert
Subkey-Type: RSA
Subkey-Length: 2048
Subkey-Usage: sign
Name-Real: Flatpak Test Key B New
Name-Email: test-key-b-new@flatpak.test
Expire-Date: 2030-01-01
%commit
EOF

FPR_B_NEW=$(gpg --list-keys --with-colons 'test-key-b-new@flatpak.test' | awk -F: '/^fpr/{print $10; exit}')
echo "Primary B-new fingerprint: $FPR_B_NEW"

# Export unsigned new key (negative test)
gpg --export "$FPR_B_NEW" > "$OUTDIR/primary-b-new-unsigned.gpg"
gpg --export-secret-keys "$FPR_B_NEW" > "$OUTDIR/primary-b-new.sec.gpg"

# Cross-sign B-new with B-old
echo "=== Cross-signing B-new with B-old ==="
gpg --batch --passphrase '' --yes --default-key "$FPR_B_OLD" --sign-key "$FPR_B_NEW"

# Export cross-signed key (includes both old and new for transition)
cat <(gpg --export "$FPR_B_OLD") <(gpg --export "$FPR_B_NEW") > "$OUTDIR/primary-b-new-crosssigned.gpg"

# Self-cross-signed: sign B-new with B-new only (no old key cert)
echo "=== Creating self-cross-signed B-new (negative test) ==="
SELF_WORK="$WORK/selfsign"
mkdir -m 700 "$SELF_WORK"
export GNUPGHOME="$SELF_WORK"

cat > "$GNUPGHOME/gpg-agent.conf" <<AGENTEOF
allow-loopback-pinentry
AGENTEOF
cat > "$GNUPGHOME/gpg.conf" <<GPGEOF
pinentry-mode loopback
GPGEOF
gpg-connect-agent "reloadagent" /bye 2>/dev/null || true

# Generate a fresh B-new-self key
gpg --batch --passphrase '' --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign cert
Subkey-Type: RSA
Subkey-Length: 2048
Subkey-Usage: sign
Name-Real: Flatpak Test Key B New Self
Name-Email: test-key-b-new-self@flatpak.test
Expire-Date: 2030-01-01
%commit
EOF

FPR_B_NEW_SELF=$(gpg --list-keys --with-colons 'test-key-b-new-self@flatpak.test' | awk -F: '/^fpr/{print $10; exit}')
echo "Self-signed B-new fingerprint: $FPR_B_NEW_SELF"

# It only has its own self-signature, no cross-signature from B-old
gpg --export "$FPR_B_NEW_SELF" > "$OUTDIR/primary-b-new-selfsigned.gpg"

export GNUPGHOME="$GNUPGHOME_SAVE"

# ======== Unrelated key ========
echo "=== Generating unrelated key ==="
gpg --batch --passphrase '' --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign cert
Subkey-Type: RSA
Subkey-Length: 2048
Subkey-Usage: sign
Name-Real: Flatpak Test Unrelated Key
Name-Email: test-unrelated@flatpak.test
Expire-Date: 2030-01-01
%commit
EOF

FPR_UNRELATED=$(gpg --list-keys --with-colons 'test-unrelated@flatpak.test' | awk -F: '/^fpr/{print $10; exit}')
gpg --export "$FPR_UNRELATED" > "$OUTDIR/unrelated.gpg"

# ======== Write key IDs to a metadata file ========
cat > "$OUTDIR/key-ids.txt" <<IDSEOF
# Auto-generated by generate-test-gpg-keys.sh — do not edit manually
# These are the short key IDs (last 8 hex chars of fingerprint)
PRIMARY_A_FPR=$FPR_A
PRIMARY_A_KEYID=${FPR_A: -8}
PRIMARY_A_SUBKEY_FPR=$SUBKEY_A_FPR
PRIMARY_A_NEWSUBKEY_FPR=$NEWSUBKEY_A_FPR
PRIMARY_B_OLD_FPR=$FPR_B_OLD
PRIMARY_B_OLD_KEYID=${FPR_B_OLD: -8}
PRIMARY_B_NEW_FPR=$FPR_B_NEW
PRIMARY_B_NEW_KEYID=${FPR_B_NEW: -8}
FPR_UNRELATED=$FPR_UNRELATED
IDSEOF

echo ""
echo "=== All keys generated in $OUTDIR ==="
ls -la "$OUTDIR"/*.gpg
echo ""
echo "Key IDs saved to $OUTDIR/key-ids.txt"
cat "$OUTDIR/key-ids.txt"
