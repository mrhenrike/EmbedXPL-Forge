/*
 * MIT License
 *
 * Copyright (c) 2020-2026 EntySec
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * Windows DLL tab plugin header.
 *
 * On Windows, tab plugins are plain DLLs loaded in-process via
 * LoadLibraryA. Each DLL exports a TabInit() function that
 * registers API handlers into a private hash table.
 * The parent dispatches requests to these handlers synchronously —
 * no child process, no pipes, no IPC overhead.
 *
 * Plugins that need pipe types additionally export TabInitPipes()
 * which registers pipe callbacks into the host's pipe table.
 *
 * Handler signature is the standard api_t:
 *     tlv_pkt_t *my_handler(c2_t *c2);
 *
 * Handlers read from c2->request and return a response TLV packet.
 */

#ifndef _TAB_DLL_H_
#define _TAB_DLL_H_

#include <pwny/api.h>
#include <pwny/tlv.h>
#include <pwny/tlv_types.h>
#include <pwny/pipe.h>

#define TAB_DLL_EXPORT __declspec(dllexport)

#define TAB_BASE 2

/*
 * DLL tab plugins export:
 *   void TabInit(api_calls_t **api_calls);
 *
 * Plugins that register pipe types additionally export:
 *   void TabInitPipes(pipes_t **pipes);
 */

#endif
