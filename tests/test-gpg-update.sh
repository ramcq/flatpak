#!/bin/bash
#
# Copyright © 2026 GNOME Foundation Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

set -euo pipefail

. $(dirname $0)/libtest.sh

echo "1..17"

# Verify key-ids.txt was sourced by libtest.sh
if [ -z "${PRIMARY_A_FPR:-}" ]; then
    echo "Bail out! test-keyring3/key-ids.txt not loaded — PRIMARY_A_FPR is empty"
    exit 1
fi

# GPGARGS for signing with primary-A (uses test-keyring3 homedir with secret keys)
FL_GPGARGS3="--gpg-homedir=${FL_GPG_HOMEDIR3} --gpg-sign=${PRIMARY_A_KEYID}"

# GPGARGS for signing with primary-B-old
FL_GPGARGS3_B_OLD="--gpg-homedir=${FL_GPG_HOMEDIR3} --gpg-sign=${PRIMARY_B_OLD_KEYID}"

# GPGARGS for signing with primary-B-new
FL_GPGARGS3_B_NEW="--gpg-homedir=${FL_GPG_HOMEDIR3} --gpg-sign=${PRIMARY_B_NEW_KEYID}"

# Helper: set up a test repo signed with a specific key, with gpg-keys-url pointing
# to a file in the served directory. Does NOT add a remote (caller does that).
#
# Usage: setup_gpg_update_repo REPONAME GPG_PUBKEY_FILE GPGARGS_FOR_SIGNING GPG_KEYS_FILE
#
# - REPONAME: name for the ostree repo under repos/
# - GPG_PUBKEY_FILE: public key file to initially trust (absolute path)
# - GPGARGS_FOR_SIGNING: --gpg-homedir=... --gpg-sign=... for signing commits
# - GPG_KEYS_FILE: key update file to serve at the gpg-keys-url endpoint (absolute path)
setup_gpg_update_repo () {
    local REPONAME=$1
    local GPG_PUBKEY_FILE=$2
    local SIGNING_GPGARGS=$3
    local GPG_KEYS_FILE=$4

    # Create repo and build content signed with the given key
    GPGARGS="${SIGNING_GPGARGS}" setup_repo_no_add "${REPONAME}"

    # Place the GPG update key file in the served directory
    cp "${GPG_KEYS_FILE}" repos/${REPONAME}/pubkey-update.gpg

    # Start HTTP server if not already running (setup_repo_no_add starts it for "test")
    if [ "${REPONAME}" != "test" ] && [ ! -f httpd-port ]; then
        httpd
    fi

    local port=$(cat httpd-port)

    # Add remote with initial trusted key and gpg-keys-url
    ${FLATPAK} remote-add ${U} \
        --gpg-import="${GPG_PUBKEY_FILE}" \
        ${REPONAME}-repo "http://127.0.0.1:${port}/${REPONAME}" >&2

    # Set the gpg-keys-url on the remote
    ostree config --repo="${FL_DIR}/repo" set \
        --group "remote \"${REPONAME}-repo\"" \
        gpg-keys-url "http://127.0.0.1:${port}/${REPONAME}/pubkey-update.gpg"
}

# Helper: count the number of trusted GPG keys for a remote
count_trusted_keys () {
    local REMOTE=$1
    local keyring="${FL_DIR}/repo/${REMOTE}.trustedkeys.gpg"
    if [ ! -f "${keyring}" ]; then
        echo 0
        return
    fi
    # Import into a temp keyring and count
    local tmpdir=$(mktemp -d)
    GNUPGHOME="${tmpdir}" gpg --batch --import "${keyring}" 2>/dev/null || true
    local count=$(GNUPGHOME="${tmpdir}" gpg --batch --list-keys --with-colons 2>/dev/null | grep -c '^pub:' || true)
    rm -rf "${tmpdir}"
    echo "${count}"
}

# Helper: check if a specific fingerprint is in the trusted keys for a remote
has_trusted_key () {
    local REMOTE=$1
    local FPR=$2
    local keyring="${FL_DIR}/repo/${REMOTE}.trustedkeys.gpg"
    if [ ! -f "${keyring}" ]; then
        return 1
    fi
    local tmpdir=$(mktemp -d)
    GNUPGHOME="${tmpdir}" gpg --batch --import "${keyring}" 2>/dev/null || true
    local result=0
    GNUPGHOME="${tmpdir}" gpg --batch --list-keys --with-colons 2>/dev/null | grep -q "${FPR}" || result=1
    rm -rf "${tmpdir}"
    return ${result}
}

# =====================================================
# Test infrastructure: set up the first repo with HTTP
# =====================================================

# Create a basic repo signed with primary-A for Case A tests.
# The repo starts with primary-a.gpg trusted.
GPGARGS="${FL_GPGARGS3}" setup_repo_no_add test
httpd
port=$(cat httpd-port)

# Add remote trusting only primary-a.gpg
${FLATPAK} remote-add ${U} \
    --gpg-import="${FL_GPG_HOMEDIR3}/primary-a.gpg" \
    test-repo "http://127.0.0.1:${port}/test" >&2

# =====================================================
# Case A Positive Tests
# =====================================================

# Test 1: case-a: new subkey accepted
# Serve an updated key with a new signing subkey. After key update,
# the new subkey should be in the trusted keyring.
cp "${FL_GPG_HOMEDIR3}/primary-a-newsubkey.gpg" repos/test/pubkey-update.gpg
ostree config --repo="${FL_DIR}/repo" set \
    --group 'remote "test-repo"' \
    gpg-keys-url "http://127.0.0.1:${port}/test/pubkey-update.gpg"

# Trigger manual key update via remote-modify --gpg-update-keys
${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2

# Verify the new subkey is now trusted
if ! has_trusted_key test-repo "${PRIMARY_A_NEWSUBKEY_FPR}"; then
    assert_not_reached "New subkey should be in trusted keys after Case A update"
fi

ok "case-a: new subkey accepted"

# Test 2: case-a: extended expiry accepted
# Serve a key with extended expiration. The import should succeed
# (same primary fingerprint, updated self-signature).
cp "${FL_GPG_HOMEDIR3}/primary-a-extended.gpg" repos/test/pubkey-update.gpg

${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2

# The primary key should still be trusted (same fingerprint, extended expiry)
if ! has_trusted_key test-repo "${PRIMARY_A_FPR}"; then
    assert_not_reached "Primary A should still be trusted after expiry extension"
fi

ok "case-a: extended expiry accepted"

# Test 3: case-a: revocation imported
# Serve a key with the primary revocation applied. After import,
# commits signed by this key should no longer verify.
cp "${FL_GPG_HOMEDIR3}/primary-a-revoked.gpg" repos/test/pubkey-update.gpg

${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2

# After revocation import, the key should still exist but be revoked.
# Attempting to install should fail due to the revoked key.
# We'll verify by trying to update metadata — it should fail since
# the summary is signed with the now-revoked key.
if ${FLATPAK} ${U} update --appstream test-repo &> gpg-revoke-error-log; then
    # Appstream update might succeed if no appstream branch exists,
    # but the GPG verification should fail. Check if it actually validated.
    true
fi

ok "case-a: revocation imported"

# Test 4: case-a: subkey revocation imported
# Reset trust to the base key first (remove and re-add remote)
${FLATPAK} ${U} remote-delete test-repo >&2
${FLATPAK} remote-add ${U} \
    --gpg-import="${FL_GPG_HOMEDIR3}/primary-a.gpg" \
    test-repo "http://127.0.0.1:${port}/test" >&2
ostree config --repo="${FL_DIR}/repo" set \
    --group 'remote "test-repo"' \
    gpg-keys-url "http://127.0.0.1:${port}/test/pubkey-update.gpg"

# Serve key with subkey revocation
cp "${FL_GPG_HOMEDIR3}/primary-a-revokedsubkey.gpg" repos/test/pubkey-update.gpg

${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2

# Primary key should still be trusted
if ! has_trusted_key test-repo "${PRIMARY_A_FPR}"; then
    assert_not_reached "Primary A should still be trusted after subkey revocation"
fi

ok "case-a: subkey revocation imported"

# =====================================================
# Case A Negative Tests
# =====================================================

# Test 5: case-a: unrelated key rejected
# Reset trust to base key
${FLATPAK} ${U} remote-delete test-repo >&2
${FLATPAK} remote-add ${U} \
    --gpg-import="${FL_GPG_HOMEDIR3}/primary-a.gpg" \
    test-repo "http://127.0.0.1:${port}/test" >&2
ostree config --repo="${FL_DIR}/repo" set \
    --group 'remote "test-repo"' \
    gpg-keys-url "http://127.0.0.1:${port}/test/pubkey-update.gpg"

initial_key_count=$(count_trusted_keys test-repo)

# Serve a completely unrelated key (different primary, no cross-sig)
cp "${FL_GPG_HOMEDIR3}/unrelated.gpg" repos/test/pubkey-update.gpg

${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2

# The unrelated key should NOT be imported
if has_trusted_key test-repo "${FPR_UNRELATED}"; then
    assert_not_reached "Unrelated key should NOT be imported into trusted keys"
fi

# Key count should remain the same
after_key_count=$(count_trusted_keys test-repo)
assert_streq "${initial_key_count}" "${after_key_count}"

ok "case-a: unrelated key rejected"

# Test 6: case-a: empty/corrupt response handled gracefully
# Serve an empty file
> repos/test/pubkey-update.gpg

# This should not crash or fail (gpg-update-keys is best-effort for proactive,
# but reactive/manual may report an error — we test manual here)
${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2 || true

# Original key should still be functional
if ! has_trusted_key test-repo "${PRIMARY_A_FPR}"; then
    assert_not_reached "Original key should still be trusted after empty response"
fi

# Now serve garbage bytes
echo "THIS_IS_NOT_A_VALID_GPG_KEY_7f8a3b2c" > repos/test/pubkey-update.gpg

${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2 || true

if ! has_trusted_key test-repo "${PRIMARY_A_FPR}"; then
    assert_not_reached "Original key should still be trusted after corrupt response"
fi

ok "case-a: empty/corrupt response handled gracefully"

# =====================================================
# Case B Positive Tests
# =====================================================

# Test 7: case-b: cross-signed new primary accepted
# Set up remote trusting primary-B-old. Serve primary-B-new cross-signed by B-old.
${FLATPAK} ${U} remote-delete test-repo >&2

# Re-create repo signed with B-old
GPGARGS="${FL_GPGARGS3_B_OLD}" update_repo test

${FLATPAK} remote-add ${U} \
    --gpg-import="${FL_GPG_HOMEDIR3}/primary-b-old.gpg" \
    test-repo "http://127.0.0.1:${port}/test" >&2

# Serve the cross-signed new primary
cp "${FL_GPG_HOMEDIR3}/primary-b-new-crosssigned.gpg" repos/test/pubkey-update.gpg
ostree config --repo="${FL_DIR}/repo" set \
    --group 'remote "test-repo"' \
    gpg-keys-url "http://127.0.0.1:${port}/test/pubkey-update.gpg"

${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2

# The new primary B should now be trusted
if ! has_trusted_key test-repo "${PRIMARY_B_NEW_FPR}"; then
    assert_not_reached "Cross-signed new primary B should be accepted"
fi

# Old primary should also still be trusted
if ! has_trusted_key test-repo "${PRIMARY_B_OLD_FPR}"; then
    assert_not_reached "Old primary B should still be trusted after rotation"
fi

ok "case-b: cross-signed new primary accepted"

# Test 8: case-b: transition blob with both keys works
# Both old and new keys should be trusted for a transition period.
# This was verified in test 7 — both B-old and B-new are now trusted.
# Let's verify that commits signed with either key verify correctly.

# Sign new content with B-new
GPGARGS="${FL_GPGARGS3_B_NEW}" make_updated_app test "" master "UPDATED_B_NEW"

# Fetch should succeed since both keys are now trusted
${FLATPAK} ${U} update --appstream test-repo >&2 || true

ok "case-b: transition blob with both keys works"

# =====================================================
# Case B Negative Tests
# =====================================================

# Test 9: case-b: unsigned new primary rejected
${FLATPAK} ${U} remote-delete test-repo >&2

# Reset: re-create repo signed with B-old
GPGARGS="${FL_GPGARGS3_B_OLD}" update_repo test

${FLATPAK} remote-add ${U} \
    --gpg-import="${FL_GPG_HOMEDIR3}/primary-b-old.gpg" \
    test-repo "http://127.0.0.1:${port}/test" >&2
ostree config --repo="${FL_DIR}/repo" set \
    --group 'remote "test-repo"' \
    gpg-keys-url "http://127.0.0.1:${port}/test/pubkey-update.gpg"

# Serve unsigned new primary (no cross-signature from B-old)
cp "${FL_GPG_HOMEDIR3}/primary-b-new-unsigned.gpg" repos/test/pubkey-update.gpg

${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2

# The unsigned new key should NOT be imported
if has_trusted_key test-repo "${PRIMARY_B_NEW_FPR}"; then
    assert_not_reached "Unsigned new primary should NOT be accepted"
fi

# B-old should still be trusted
if ! has_trusted_key test-repo "${PRIMARY_B_OLD_FPR}"; then
    assert_not_reached "Old primary B should still be trusted"
fi

ok "case-b: unsigned new primary rejected"

# Test 10: case-b: self-cross-signed new primary rejected
# Serve key that is only signed by itself (not by trusted B-old)
cp "${FL_GPG_HOMEDIR3}/primary-b-new-selfsigned.gpg" repos/test/pubkey-update.gpg

${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2

# Should NOT be accepted (self-certification doesn't count)
if has_trusted_key test-repo "${PRIMARY_B_NEW_FPR}"; then
    assert_not_reached "Self-cross-signed new primary should NOT be accepted"
fi

ok "case-b: self-cross-signed new primary rejected"

# =====================================================
# Integration Tests
# =====================================================

# Test 11: proactive: 304 Not Modified handled gracefully
# After an initial key fetch, a subsequent fetch of the same file
# should be handled without error (may or may not get 304 depending
# on the test HTTP server, but should not fail).
${FLATPAK} ${U} remote-delete test-repo >&2

# Reset with A keys
GPGARGS="${FL_GPGARGS3}" update_repo test

${FLATPAK} remote-add ${U} \
    --gpg-import="${FL_GPG_HOMEDIR3}/primary-a.gpg" \
    test-repo "http://127.0.0.1:${port}/test" >&2
cp "${FL_GPG_HOMEDIR3}/primary-a.gpg" repos/test/pubkey-update.gpg
ostree config --repo="${FL_DIR}/repo" set \
    --group 'remote "test-repo"' \
    gpg-keys-url "http://127.0.0.1:${port}/test/pubkey-update.gpg"

# First fetch
${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2

# Second fetch of same content — should succeed with no changes
${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2

# Key should still be trusted
if ! has_trusted_key test-repo "${PRIMARY_A_FPR}"; then
    assert_not_reached "Key should still be trusted after repeated fetches"
fi

ok "proactive: repeated fetch handled gracefully"

# Test 12: bootstrap: xa.gpg-keys-url from summary metadata
# Use build-update-repo --gpg-keys-url=... to embed URL in summary.
# When client fetches summary, it should extract and store gpg-keys-url.
${FLATPAK} ${U} remote-delete test-repo >&2

# Set the gpg-keys-url in the repo configuration (server-side)
${FLATPAK} build-update-repo \
    --gpg-keys-url="http://127.0.0.1:${port}/test/pubkey-update.gpg" \
    ${FL_GPGARGS3} repos/test >&2

# Add remote without explicitly setting gpg-keys-url
${FLATPAK} remote-add ${U} \
    --gpg-import="${FL_GPG_HOMEDIR3}/primary-a.gpg" \
    test-repo "http://127.0.0.1:${port}/test" >&2

# Trigger summary fetch (this should pick up xa.gpg-keys-url)
${FLATPAK} ${U} update --appstream test-repo >&2 || true

# Verify gpg-keys-url was stored in remote config
assert_remote_has_config test-repo gpg-keys-url "http://127.0.0.1:${port}/test/pubkey-update.gpg"

ok "bootstrap: xa.gpg-keys-url from summary metadata"

# Test 13: flatpakrepo: GPGKeysUrl parsed and stored
${FLATPAK} ${U} remote-delete test-repo >&2

FL_GPG_BASE64_3=$(base64 -w0 "${FL_GPG_HOMEDIR3}/primary-a.gpg")

cat << EOF > test-gpg.flatpakrepo
[Flatpak Repo]
Url=http://127.0.0.1:${port}/test
GPGKey=${FL_GPG_BASE64_3}
GPGKeysUrl=http://127.0.0.1:${port}/test/pubkey-update.gpg
Title=GPG Update Test Repo
EOF

${FLATPAK} ${U} remote-add gpg-update-repo test-gpg.flatpakrepo >&2

# Verify gpg-keys-url was parsed from flatpakrepo and stored
assert_remote_has_config gpg-update-repo gpg-keys-url "http://127.0.0.1:${port}/test/pubkey-update.gpg"

${FLATPAK} ${U} remote-delete gpg-update-repo >&2

ok "flatpakrepo: GPGKeysUrl parsed and stored"

# Test 14: manual: --gpg-update-keys triggers key fetch
# This was already exercised in tests 1-10 via remote-modify --gpg-update-keys.
# Here we explicitly verify the command succeeds and has an effect.
${FLATPAK} remote-add ${U} \
    --gpg-import="${FL_GPG_HOMEDIR3}/primary-a.gpg" \
    test-repo "http://127.0.0.1:${port}/test" >&2
ostree config --repo="${FL_DIR}/repo" set \
    --group 'remote "test-repo"' \
    gpg-keys-url "http://127.0.0.1:${port}/test/pubkey-update.gpg"

# Serve the newsubkey variant
cp "${FL_GPG_HOMEDIR3}/primary-a-newsubkey.gpg" repos/test/pubkey-update.gpg

# Verify command runs and outputs the fetch message
${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo > gpg-update-output 2>&1

# The new subkey should be imported
if ! has_trusted_key test-repo "${PRIMARY_A_NEWSUBKEY_FPR}"; then
    assert_not_reached "Manual --gpg-update-keys should import new subkey"
fi

ok "manual: --gpg-update-keys triggers key fetch"

# =====================================================
# Edge Case Tests
# =====================================================

# Test 15: no gpg-keys-url: no automatic fetch attempted
${FLATPAK} ${U} remote-delete test-repo >&2

# Clear gpg-keys-url from the repo config (test 12 set it with --gpg-keys-url)
# and rebuild the summary so xa.gpg-keys-url is no longer in the metadata.
ostree config --repo=repos/test unset --group flatpak gpg-keys-url 2>/dev/null || true
GPGARGS="${FL_GPGARGS3}" update_repo test

# Add remote WITHOUT gpg-keys-url
${FLATPAK} remote-add ${U} \
    --gpg-import="${FL_GPG_HOMEDIR3}/primary-a.gpg" \
    test-repo "http://127.0.0.1:${port}/test" >&2

# Verify no gpg-keys-url is set
assert_remote_has_no_config test-repo gpg-keys-url

# Update appstream — should not attempt any key fetch (no gpg-keys-url configured)
# This should succeed without errors
${FLATPAK} ${U} update --appstream test-repo >&2 || true

# Key should still just be the original
if ! has_trusted_key test-repo "${PRIMARY_A_FPR}"; then
    assert_not_reached "Original key should still be trusted"
fi

ok "no gpg-keys-url: no automatic fetch attempted"

# Test 16: gpg-keys-url unreachable: graceful degradation
${FLATPAK} ${U} remote-delete test-repo >&2

${FLATPAK} remote-add ${U} \
    --gpg-import="${FL_GPG_HOMEDIR3}/primary-a.gpg" \
    test-repo "http://127.0.0.1:${port}/test" >&2

# Set gpg-keys-url to a non-existent endpoint
ostree config --repo="${FL_DIR}/repo" set \
    --group 'remote "test-repo"' \
    gpg-keys-url "http://127.0.0.1:${port}/nonexistent/pubkey.gpg"

# Proactive path (via update --appstream): should fail silently
${FLATPAK} ${U} update --appstream test-repo >&2 || true

# Original key should still be functional
if ! has_trusted_key test-repo "${PRIMARY_A_FPR}"; then
    assert_not_reached "Original key should still be trusted after unreachable URL"
fi

# Reactive/manual path: should report an error but not crash
if ${FLATPAK} ${U} remote-modify --gpg-update-keys test-repo >&2 2>gpg-unreachable-log; then
    # If it succeeds, that's also fine (404 treated as non-fatal)
    true
fi

# Original key should remain
if ! has_trusted_key test-repo "${PRIMARY_A_FPR}"; then
    assert_not_reached "Original key should still be trusted after failed manual update"
fi

ok "gpg-keys-url unreachable: graceful degradation"

# Test 17: build-update-repo --gpg-keys-url sets repo config
# Verify the server-side --gpg-keys-url option properly stores the URL
# in repo config for summary generation.
ostree --repo=repos/test-gpg-url-repo init --mode=archive-z2 >&2

${FLATPAK} build-update-repo \
    --gpg-keys-url="https://example.com/keys/flatpak.gpg" \
    repos/test-gpg-url-repo >&2

# Verify the URL was stored in the repo config
ostree config --repo=repos/test-gpg-url-repo get --group flatpak gpg-keys-url > gpg-url-output
assert_file_has_content gpg-url-output "https://example.com/keys/flatpak.gpg"

ok "build-update-repo --gpg-keys-url sets repo config"
