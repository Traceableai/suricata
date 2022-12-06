/* Copyright (C) 2007-2013 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Giuseppe Longo <giuseppelng@gmail.com>
 *
 */

#ifndef DEFRAG_CONFIG_H_
#define DEFRAG_CONFIG_H_

#include "decode.h"

void DefragSetDefaultTimeout(intmax_t timeout);
void DefragPolicyLoadFromConfig(void);
int DefragPolicyGetHostTimeout(Packet *p);
void DefragTreeDestroy(void);

#endif /* DEFRAG_CONFIG_H_ */
