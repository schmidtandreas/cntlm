/*
 * These are BASIC authentication routines for the main module of CNTLM
 *
 * CNTLM is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * CNTLM is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Copyright (c) 2019 Andreas Schmidt
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "basic.h"
#include "utils.h"

char *basic_hash_password(const char *username, const char *domain,
			  const char *password) {
	char *buf, *passbasic;
	int buflen = strlen(username) + strlen(password) + 2;
	unsigned int basiclen, ret;

	buf = new(buflen);
	snprintf(buf, buflen, "%s:%s", username, password);

	basiclen = b64e_size(strlen(buf)) + 10;
	if (!basiclen) {
		free(buf);
		return NULL;
	}

	passbasic = new(basiclen);
	to_base64(passbasic, buf, strlen(buf), basiclen);

	free(buf);

	return passbasic;
}
