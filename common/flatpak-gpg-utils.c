/* vi:set et sw=2 sts=2 cin cino=t0,f0,(0,{s,>2s,n-s,^-s,e-s:
 * Copyright © 2026 GNOME Foundation Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <string.h>

#include <glib/gi18n-lib.h>

#include <gpgme.h>
#include <ostree.h>

#include "libglnx.h"
#include "flatpak-gpg-utils.h"

G_DEFINE_AUTO_CLEANUP_FREE_FUNC (gpgme_data_t, gpgme_data_release, NULL)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC (gpgme_ctx_t, gpgme_release, NULL)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC (gpgme_key_t, gpgme_key_unref, NULL)

static void
flatpak_gpg_error_to_gio_error (gpgme_error_t  gpg_error,
                                GError       **error)
{
  GIOErrorEnum errcode;

  switch (gpgme_err_code (gpg_error))
    {
    case GPG_ERR_NO_ERROR:
      g_return_if_reached ();

    case GPG_ERR_ENOMEM:
      g_error ("%s: out of memory",
               gpgme_strsource (gpg_error));

    case GPG_ERR_INV_VALUE:
      errcode = G_IO_ERROR_INVALID_ARGUMENT;
      break;

    default:
      errcode = G_IO_ERROR_FAILED;
      break;
    }

  g_set_error (error, G_IO_ERROR, errcode, "%s: error code %d",
               gpgme_strsource (gpg_error), gpgme_err_code (gpg_error));
}

/* Collect fingerprints of keys currently trusted for a remote.
 * Returns a hash table of fingerprint strings (keys are owned by the table). */
static GHashTable *
collect_trusted_fingerprints (OstreeRepo    *repo,
                              const char    *remote_name,
                              GCancellable  *cancellable,
                              GError       **error)
{
  g_autoptr(GHashTable) fps = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  g_autoptr(GPtrArray) keys = NULL;

  if (!ostree_repo_remote_get_gpg_keys (repo, remote_name, NULL,
                                        &keys, cancellable, error))
    return NULL;

  for (guint i = 0; i < keys->len; i++)
    {
      GVariant *key = g_ptr_array_index (keys, i);
      g_autoptr(GVariant) subkeys = NULL;

      /* Each key is (aa{sv} aa{sv} a{sv}):
       *   element 0 = array of subkey dicts (primary is first)
       *   element 1 = array of UID dicts
       *   element 2 = metadata dict
       * The fingerprint is in the first subkey dict. */
      subkeys = g_variant_get_child_value (key, 0);
      if (subkeys != NULL && g_variant_n_children (subkeys) > 0)
        {
          g_autoptr(GVariant) primary_subkey = g_variant_get_child_value (subkeys, 0);
          const char *fingerprint = NULL;

          if (g_variant_lookup (primary_subkey, "fingerprint", "&s", &fingerprint))
            g_hash_table_add (fps, g_strdup (fingerprint));
        }
    }

  return g_steal_pointer (&fps);
}

/* Validate a candidate GPG key blob against the existing trusted keys for a remote.
 *
 * This implements two cases from the key update design:
 *
 * Case A (In-Place Update): The candidate shares a primary fingerprint with an
 * existing trusted key but contains new subkeys, updated self-signatures (e.g.
 * extended expiry), or revocation packets. GPGME's import validates binding
 * signatures, so invalid material is rejected.
 *
 * Case B (New Primary): The candidate contains a new primary key that carries
 * valid certification cross-signatures from an existing trusted primary. We
 * verify this by importing both into a temporary keyring, then checking that
 * at least one UID certification on the new key was made by a pre-existing
 * trusted key.
 *
 * Returns TRUE on success (including "no update needed"). Sets out_case and
 * out_importable_keys to indicate what was found.
 */
gboolean
flatpak_gpg_validate_key_update (OstreeRepo              *repo,
                                 const char              *remote_name,
                                 GBytes                  *candidate_keys,
                                 FlatpakGpgKeyUpdateCase *out_case,
                                 GBytes                 **out_importable_keys,
                                 GCancellable            *cancellable,
                                 GError                 **error)
{
  g_auto(gpgme_ctx_t) context = NULL;
  gpgme_error_t gpg_error;
  g_auto(GLnxTmpDir) tmpdir = { 0, };
  g_autofree char *tmp_dir_pattern = NULL;
  g_autoptr(GHashTable) trusted_fps = NULL;
  g_autoptr(GFile) keyring_file = NULL;
  g_autofree char *keyring_name = NULL;
  g_auto(gpgme_data_t) candidate_data = NULL;
  gpgme_import_result_t import_result;
  gpgme_import_status_t status;
  gboolean has_in_place_update = FALSE;
  gboolean has_new_primary = FALSE;
  g_autoptr(GPtrArray) new_primary_fps = NULL;

  g_return_val_if_fail (out_case != NULL, FALSE);
  g_return_val_if_fail (out_importable_keys != NULL, FALSE);

  *out_case = FLATPAK_GPG_KEY_UPDATE_NONE;
  *out_importable_keys = NULL;

  if (candidate_keys == NULL || g_bytes_get_size (candidate_keys) == 0)
    return TRUE;

  /* Step 1: Collect fingerprints of currently-trusted keys */
  trusted_fps = collect_trusted_fingerprints (repo, remote_name, cancellable, error);
  if (trusted_fps == NULL)
    return FALSE;

  if (g_hash_table_size (trusted_fps) == 0)
    {
      g_debug ("No trusted keys for remote %s, cannot validate update", remote_name);
      return TRUE;
    }

  /* Step 2: Create temporary GPGME homedir and import existing trusted keys */
  tmp_dir_pattern = g_build_filename (g_get_tmp_dir (), "flatpak-gpg-update-XXXXXX", NULL);
  if (!glnx_mkdtempat (AT_FDCWD, tmp_dir_pattern, 0700, &tmpdir, error))
    return FALSE;

  gpg_error = gpgme_new (&context);
  if (gpg_error != GPG_ERR_NO_ERROR)
    {
      flatpak_gpg_error_to_gio_error (gpg_error, error);
      g_prefix_error (error, "Unable to create GPG context: ");
      return FALSE;
    }

  gpg_error = gpgme_ctx_set_engine_info (context, GPGME_PROTOCOL_OpenPGP,
                                         NULL, tmpdir.path);
  if (gpg_error != GPG_ERR_NO_ERROR)
    {
      flatpak_gpg_error_to_gio_error (gpg_error, error);
      g_prefix_error (error, "Unable to set GPG homedir: ");
      return FALSE;
    }

  /* Copy the remote's trusted keyring into our temp homedir */
  keyring_name = g_strdup_printf ("%s.trustedkeys.gpg", remote_name);
  keyring_file = g_file_get_child (ostree_repo_get_path (repo), keyring_name);

  if (g_file_query_exists (keyring_file, NULL))
    {
      if (!glnx_file_copy_at (AT_FDCWD, g_file_peek_path (keyring_file), NULL,
                              tmpdir.fd, "pubring.gpg",
                              GLNX_FILE_COPY_OVERWRITE | GLNX_FILE_COPY_NOXATTRS,
                              cancellable, error))
        return FALSE;
    }

  /* Step 3: Import candidate key blob */
  gpg_error = gpgme_data_new_from_mem (&candidate_data,
                                       g_bytes_get_data (candidate_keys, NULL),
                                       g_bytes_get_size (candidate_keys),
                                       0 /* do not copy */);
  if (gpg_error != GPG_ERR_NO_ERROR)
    {
      flatpak_gpg_error_to_gio_error (gpg_error, error);
      g_prefix_error (error, "Unable to create data buffer for candidate keys: ");
      return FALSE;
    }

  gpg_error = gpgme_op_import (context, candidate_data);
  if (gpg_error != GPG_ERR_NO_ERROR)
    {
      flatpak_gpg_error_to_gio_error (gpg_error, error);
      g_prefix_error (error, "Unable to import candidate keys: ");
      return FALSE;
    }

  /* Step 4: Analyze import results */
  import_result = gpgme_op_import_result (context);
  if (import_result == NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "No import result available");
      return FALSE;
    }

  new_primary_fps = g_ptr_array_new_with_free_func (g_free);

  for (status = import_result->imports; status != NULL; status = status->next)
    {
      if (status->result != GPG_ERR_NO_ERROR)
        continue;

      if (status->status & GPGME_IMPORT_NEW)
        {
          /* New primary key — needs Case B cross-signature validation */
          has_new_primary = TRUE;
          g_ptr_array_add (new_primary_fps, g_strdup (status->fpr));
        }
      else if (status->status & (GPGME_IMPORT_UID | GPGME_IMPORT_SIG | GPGME_IMPORT_SUBKEY))
        {
          /* In-place update to existing key — Case A */
          has_in_place_update = TRUE;
        }
      /* status == 0 means GPGME_IMPORT_NO_CHANGE — already current */
    }

  /* Step 5: Handle Case A — in-place updates */
  if (has_in_place_update && !has_new_primary)
    {
      *out_case = FLATPAK_GPG_KEY_UPDATE_IN_PLACE;
      *out_importable_keys = g_bytes_ref (candidate_keys);
      g_debug ("GPG key update for remote %s: in-place update (Case A)", remote_name);
      return TRUE;
    }

  /* Step 6: Handle Case B — new primary with cross-signature validation */
  if (has_new_primary)
    {
      gboolean any_valid_cross_sig = FALSE;

      gpgme_set_keylist_mode (context,
                              GPGME_KEYLIST_MODE_LOCAL | GPGME_KEYLIST_MODE_SIGS);

      for (guint i = 0; i < new_primary_fps->len; i++)
        {
          const char *new_fpr = g_ptr_array_index (new_primary_fps, i);
          g_auto(gpgme_key_t) new_key = NULL;

          gpg_error = gpgme_get_key (context, new_fpr, &new_key, 0);
          if (gpg_error != GPG_ERR_NO_ERROR)
            continue;

          /* Check each UID's certification signatures.
           * sig->keyid is a 16-hex-character long key ID. We match it
           * against the tail of trusted fingerprints. */
          for (gpgme_user_id_t uid = new_key->uids; uid != NULL; uid = uid->next)
            {
              for (gpgme_key_sig_t sig = uid->signatures; sig != NULL; sig = sig->next)
                {
                  /* Skip self-signatures: compare sig->keyid against the
                   * tail of the new key's fingerprint */
                  if (sig->keyid != NULL)
                    {
                      gsize new_fpr_len = strlen (new_fpr);
                      gsize sig_keyid_len = strlen (sig->keyid);
                      if (new_fpr_len >= sig_keyid_len &&
                          g_ascii_strcasecmp (new_fpr + new_fpr_len - sig_keyid_len,
                                              sig->keyid) == 0)
                        continue;
                    }

                  /* sig->status == GPG_ERR_NO_ERROR means the signature verified */
                  if (sig->status != GPG_ERR_NO_ERROR)
                    continue;

                  /* Check if the signing key was already in our trusted keyring
                   * (not just in the candidate blob). Match sig->keyid against
                   * the tail of each trusted fingerprint. */
                  if (sig->keyid != NULL)
                    {
                      gsize sig_keyid_len = strlen (sig->keyid);
                      GHashTableIter iter;
                      gpointer key;
                      g_hash_table_iter_init (&iter, trusted_fps);
                      while (g_hash_table_iter_next (&iter, &key, NULL))
                        {
                          const char *trusted_fpr = key;
                          gsize trusted_fpr_len = strlen (trusted_fpr);
                          if (trusted_fpr_len >= sig_keyid_len &&
                              g_ascii_strcasecmp (trusted_fpr + trusted_fpr_len - sig_keyid_len,
                                                  sig->keyid) == 0)
                            {
                              any_valid_cross_sig = TRUE;
                              g_debug ("New primary %s has valid cross-signature from "
                                       "trusted key ID %s", new_fpr, sig->keyid);
                              break;
                            }
                        }
                    }

                  if (any_valid_cross_sig)
                    break;
                }
              if (any_valid_cross_sig)
                break;
            }

          if (any_valid_cross_sig)
            break;
        }

      if (any_valid_cross_sig)
        {
          *out_case = FLATPAK_GPG_KEY_UPDATE_NEW_PRIMARY;
          *out_importable_keys = g_bytes_ref (candidate_keys);
          g_debug ("GPG key update for remote %s: new cross-signed primary (Case B)",
                   remote_name);
          return TRUE;
        }
      else
        {
          g_debug ("GPG key update for remote %s: new primary found but no valid "
                   "cross-signature from trusted key — rejecting", remote_name);
          /* Not an error, just not accepted */
          return TRUE;
        }
    }

  /* No changes or only unchanged keys */
  g_debug ("GPG key update for remote %s: no new key material", remote_name);
  return TRUE;
}
