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
 * Minimal getuid handler — returns current thread/process identity.
 *
 * Kept in the core (not a plugin) because the getuid command is
 * always loaded and only performs a benign identity query.
 *
 * Offensive token operations (steal, make, rev2self) live in
 * the token tab plugin instead.
 */

#ifndef _GETUID_H_
#define _GETUID_H_

#include <windows.h>
#include <string.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/misc.h>
#include <pwny/log.h>

#define TOKEN_BASE 21

#define TOKEN_GETUID \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TOKEN_BASE, \
                       API_CALL + 2)

#define TLV_TYPE_TOKEN_USER TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TOKEN_BASE, API_TYPE)

static int getuid_get_username(HANDLE hToken, char *buf, size_t buf_size)
{
    BYTE tokenInfo[4096];
    DWORD dwSize;
    WCHAR cbUser[512], cbDomain[512];
    DWORD dwUserSize = sizeof(cbUser);
    DWORD dwDomainSize = sizeof(cbDomain);
    DWORD dwSidType = 0;
    char *domain;
    char *user;

    if (!GetTokenInformation(hToken, TokenUser, tokenInfo,
                             sizeof(tokenInfo), &dwSize))
    {
        return -1;
    }

    if (!LookupAccountSidW(NULL, ((TOKEN_USER *)tokenInfo)->User.Sid,
                           cbUser, &dwUserSize, cbDomain,
                           &dwDomainSize, (PSID_NAME_USE)&dwSidType))
    {
        return -1;
    }

    domain = wchar_to_utf8(cbDomain);
    user = wchar_to_utf8(cbUser);

    if (domain == NULL || user == NULL)
    {
        free(domain);
        free(user);
        return -1;
    }

    _snprintf(buf, buf_size, "%s\\%s", domain, user);
    buf[buf_size - 1] = '\0';

    free(domain);
    free(user);

    return 0;
}

static tlv_pkt_t *token_getuid(c2_t *c2)
{
    HANDLE hToken;
    char username[1024];
    tlv_pkt_t *result;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken))
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        {
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        }
    }

    if (getuid_get_username(hToken, username, sizeof(username)) != 0)
    {
        CloseHandle(hToken);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    CloseHandle(hToken);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_TOKEN_USER, username);

    return result;
}

void register_getuid_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, TOKEN_GETUID, token_getuid);
}

#endif
