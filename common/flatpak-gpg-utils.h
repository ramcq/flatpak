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

#pragma once

#include <ostree.h>
#include <gio/gio.h>

G_BEGIN_DECLS

typedef enum {
  FLATPAK_GPG_KEY_UPDATE_NONE,        /* No new key material */
  FLATPAK_GPG_KEY_UPDATE_IN_PLACE,    /* Case A: same primary, new subkeys/sigs/expiry */
  FLATPAK_GPG_KEY_UPDATE_NEW_PRIMARY, /* Case B: new primary with valid cross-sig */
} FlatpakGpgKeyUpdateCase;

gboolean flatpak_gpg_validate_key_update (OstreeRepo              *repo,
                                          const char              *remote_name,
                                          GBytes                  *candidate_keys,
                                          FlatpakGpgKeyUpdateCase *out_case,
                                          GBytes                 **out_importable_keys,
                                          GCancellable            *cancellable,
                                          GError                 **error);

G_END_DECLS
