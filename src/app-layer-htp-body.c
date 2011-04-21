/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * This file provides a HTTP protocol support for the engine using HTP library.
 */

#include "suricata.h"
#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-radix-tree.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "util-spm.h"
#include "util-debug.h"
#include "app-layer-htp.h"
#include "app-layer-htp-file.h"
#include "util-time.h"
#include <htp/htp.h>

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "flow-util.h"
#include "flow-file.h"

#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-parse.h"

#include "conf.h"

#include "util-memcmp.h"

/**
 * \brief Append a chunk of body to the HtpBody struct
 *
 * \param body pointer to the HtpBody holding the list
 * \param data pointer to the data of the chunk
 * \param len length of the chunk pointed by data
 *
 * \retval 0 ok
 * \retval -1 error
 */
int HtpBodyAppendChunk(SCHtpTxUserData *htud, HtpBody *body, uint8_t *data, uint32_t len)
{
    SCEnter();

    HtpBodyChunk *bd = NULL;

    if (len == 0 || data == NULL) {
        SCReturnInt(0);
    }

    if (body->nchunks == 0) {
        /* New chunk */
        bd = (HtpBodyChunk *)SCMalloc(sizeof(HtpBodyChunk));
        if (bd == NULL)
            goto error;

        bd->len = len;
        bd->stream_offset = 0;
        bd->next = NULL;
        bd->id = 0;

        bd->data = SCMalloc(len);
        if (bd->data == NULL) {
            goto error;
        }
        memcpy(bd->data, data, len);

        body->first = body->last = bd;
        body->nchunks++;

        htud->content_len_so_far = len;
    } else {
        bd = (HtpBodyChunk *)SCMalloc(sizeof(HtpBodyChunk));
        if (bd == NULL)
            goto error;

        bd->len = len;
        bd->stream_offset = htud->content_len_so_far;
        bd->next = NULL;
        bd->id = body->nchunks + 1;

        bd->data = SCMalloc(len);
        if (bd->data == NULL) {
            goto error;
        }
        memcpy(bd->data, data, len);

        body->last->next = bd;
        body->last = bd;
        body->nchunks++;

        htud->content_len_so_far += len;
    }
    SCLogDebug("Body %p; Chunk id: %"PRIu32", data %p, len %"PRIu32"", body,
                bd->id, bd->data, (uint32_t)bd->len);

    SCReturnInt(0);

error:
    if (bd != NULL) {
        if (bd->data != NULL) {
            SCFree(bd->data);
        }
        SCFree(bd->data);
    }
    SCReturnInt(-1);
}

/**
 * \brief Print the information and chunks of a Body
 * \param body pointer to the HtpBody holding the list
 * \retval none
 */
void HtpBodyPrint(HtpBody *body)
{
    if (SCLogDebugEnabled()||1) {
        SCEnter();

        if (body->nchunks == 0)
            return;

        HtpBodyChunk *cur = NULL;
        SCLogDebug("--- Start body chunks at %p ---", body);
        printf("--- Start body chunks at %p ---\n", body);
        for (cur = body->first; cur != NULL; cur = cur->next) {
            SCLogDebug("Body %p; Chunk id: %"PRIu32", data %p, len %"PRIu32"\n",
                        body, cur->id, cur->data, (uint32_t)cur->len);
            printf("Body %p; Chunk id: %"PRIu32", data %p, len %"PRIu32"\n",
                        body, cur->id, cur->data, (uint32_t)cur->len);
            PrintRawDataFp(stdout, (uint8_t*)cur->data, cur->len);
        }
        SCLogDebug("--- End body chunks at %p ---", body);
    }
}

/**
 * \brief Free the information held in the request body
 * \param body pointer to the HtpBody holding the list
 * \retval none
 */
void HtpBodyFree(HtpBody *body)
{
    SCEnter();

    if (body->nchunks == 0)
        return;

    SCLogDebug("Removing chunks of Body %p; Last Chunk id: %"PRIu32", data %p,"
               " len %"PRIu32, body, body->last->id, body->last->data,
                (uint32_t)body->last->len);
    body->nchunks = 0;

    HtpBodyChunk *cur = NULL;
    HtpBodyChunk *prev = NULL;

    prev = body->first;
    while (prev != NULL) {
        cur = prev->next;
        if (prev->data != NULL)
            SCFree(prev->data);
        SCFree(prev);
        prev = cur;
    }
    body->first = body->last = NULL;
    body->operation = HTP_BODY_NONE;
}

/**
 * \brief Free request body chunks that are already fully parsed.
 *
 * \param htud pointer to the SCHtpTxUserData holding the body
 *
 * \retval none
 */
void HtpBodyPrune(SCHtpTxUserData *htud)
{
    SCEnter();

    HtpBody *body = &htud->body;

    if (body->nchunks == 0) {
        SCReturn;
    }

    if (htud->body_parsed == 0) {
        SCReturn;
    }

    SCLogDebug("Pruning chunks of Body %p; Last Chunk id: %"PRIu32", data %p,"
               " len %"PRIu32, body, body->last->id, body->last->data,
                (uint32_t)body->last->len);

    HtpBodyChunk *cur = NULL;

    cur = body->first;

    while (cur != NULL) {
        HtpBodyChunk *next = cur->next;

        SCLogDebug("cur->stream_offset %"PRIu64" + cur->len %u = %"PRIu64", "
                "htud->body_parsed %"PRIu64, cur->stream_offset, cur->len,
                cur->stream_offset + cur->len, htud->body_parsed);

        if ((cur->stream_offset + cur->len) >= htud->body_parsed) {
            break;
        }

        body->first = next;
        if (body->last == cur) {
            body->last = next;
        }

        if (body->nchunks > 0)
            body->nchunks--;

        if (cur->data != NULL) {
            SCFree(cur->data);
        }
        SCFree(cur);

        cur = next;
    }

    SCReturn;
}
