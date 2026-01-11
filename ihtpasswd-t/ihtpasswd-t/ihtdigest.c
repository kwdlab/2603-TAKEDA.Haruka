/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/******************************************************************************
 ******************************************************************************
 * NOTE! This program is not safe as a setuid executable!  Do not make it
 * setuid!
 ******************************************************************************
 *****************************************************************************/
/*
 * htdigest.c: simple program for manipulating digest passwd file for Apache
 *
 * by Alexei Kosut, based on htpasswd.c, by Rob McCool
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <iconv.h>

#include <uchardet/uchardet.h>
#include <utf8proc.h>

#include <openssl/md5.h>
#include "apr.h"
#include "apr_file_io.h"
#include "apr_md5.h"
#include "apr_lib.h"            /* for apr_getpass() */
#include "apr_general.h"
#include "apr_signal.h"
#include "apr_strings.h"        /* for apr_pstrdup() */

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef WIN32
#include <conio.h>
#endif


#if APR_CHARSET_EBCDIC
#define LF '\n'
#define CR '\r'
#else
#define LF 10
#define CR 13
#endif /* APR_CHARSET_EBCDIC */

#define MAX_STRING_LEN 256
#define MAX_LINE_LEN 768

apr_file_t *tfp = NULL;
apr_file_t *errfile;
apr_pool_t *cntxt;
#if APR_CHARSET_EBCDIC
apr_xlate_t *to_ascii;
#endif

static void cleanup_tempfile_and_exit(int rc)
{
    if (tfp) {
        apr_file_close(tfp);
    }
    exit(rc);
}

static int getword(char *word, char *line, char stop)
{
    int x = 0, y;

    for (x = 0; ((line[x]) && (line[x] != stop)); x++) {
        if (x == (MAX_STRING_LEN - 1)) {
            return 1;
        }
        word[x] = line[x];
    }

    word[x] = '\0';
    if (line[x])
        ++x;
    y = 0;

    while ((line[y++] = line[x++]));

    return 0;
}

static int get_line(char *s, int n, apr_file_t *f)
{
    int i = 0;
    char ch;
    apr_status_t rv = APR_EINVAL;

    /* we need 2 remaining bytes in buffer */
    while (i < (n - 2) &&
           ((rv = apr_file_getc(&ch, f)) == APR_SUCCESS) && (ch != '\n')) {
        s[i++] = ch;
    }
    /* First remaining byte potentially used here */
    if (ch == '\n')
        s[i++] = ch;
    /* Second remaining byte used here */
    s[i] = '\0';

    if (rv != APR_SUCCESS)
        return 1;

    return 0;
}

static void putline(apr_file_t *f, char *l)
{
    int x;

    for (x = 0; l[x]; x++)
        apr_file_putc(l[x], f);
}

/* H. Takeda:
 * RFC 7613 に基づき、入力文字列を UTF-8 に変換し NFC 正規化する
 */
static char *convert_and_normalize_utf8(const char *input)
{
   if (!input)
        return NULL;

    size_t len = strlen(input);

    uchardet_t ud = uchardet_new();
    if (!ud)
        return NULL;
    uchardet_handle_data(ud, input, len);
    uchardet_data_end(ud);

    const char *charset = uchardet_get_charset(ud);
    if (!charset || !*charset)
        charset = "UTF-8";

    iconv_t cd = iconv_open("UTF-8", charset);
    if (cd == (iconv_t)-1) {
        perror("iconv_open");
        exit(1);
    }

    size_t inbytes = len;
    size_t outbytes = len * 4 + 1;
 char *inbuf = strdup(input);
    char *outbuf = malloc(outbytes);
    char *pin = inbuf;
    char *pout = outbuf;

    if (iconv(cd, &pin, &inbytes, &pout, &outbytes) == (size_t)-1) {
        perror("iconv");
        exit(1);
    }
    *pout = '\0';

    iconv_close(cd);
    uchardet_delete(ud);
    free(inbuf);

    /* NFC 正規化 */
    utf8proc_uint8_t *normalized =
        utf8proc_NFC((const utf8proc_uint8_t *)outbuf);
    if (!normalized) {
        fprintf(stderr, "utf8proc_NFC failed\n");
        exit(1);
    }

    free(outbuf);
    return (char *)normalized; /* malloc 領域 */
}

static void add_password(const char *user, const char *realm, apr_file_t *f)
{
    char *pw;
    apr_md5_ctx_t context;
    unsigned char digest[16];
    char string[MAX_LINE_LEN]; /* this includes room for 2 * ':' + '\0' */
    char pwin[MAX_STRING_LEN];
    char pwv[MAX_STRING_LEN];
    unsigned int i;
    apr_size_t len = sizeof(pwin);

    if (apr_password_get("New password: ", pwin, &len) != APR_SUCCESS) {
        apr_file_printf(errfile, "password too long");
        cleanup_tempfile_and_exit(5);
    }
    len = sizeof(pwin);
    apr_password_get("Re-type new password: ", pwv, &len);
    if (strcmp(pwin, pwv) != 0) {
        apr_file_printf(errfile, "They don't match, sorry.\n");
        cleanup_tempfile_and_exit(1);
    }
/* H. Takeda:
 * Digest 認証の 3 要素を UTF-8 + NFC に統一する
 */
   char *u8_user  = convert_and_normalize_utf8(user);
   char *u8_realm = convert_and_normalize_utf8(realm);
   char *u8_pw    = convert_and_normalize_utf8(pw);
   if (!u8_user || !u8_realm || !u8_pw) {
    apr_file_printf(errfile, "UTF-8 normalization failed\n");
    free(u8_user);
    free(u8_realm);
    free(u8_pw);
    cleanup_tempfile_and_exit(1);
}
/* RFC 7616 */
   apr_snprintf(string, sizeof(string), "%s:%s:%s", u8_user, u8_realm, u8_pw);

   free(u8_user);
   free(u8_realm);
   free(u8_pw);


    /* Do MD5 stuff */
   apr_md5_init(&context);
   apr_md5_update(&context, string, strlen(string));
   apr_md5_final(digest, &context);
#if APR_CHARSET_EBCDIC
    apr_md5_set_xlate(&context, to_ascii);
#endif
    apr_md5_update(&context, (unsigned char *) string, strlen(string));
    apr_md5_final(digest, &context);

    for (i = 0; i < 16; i++)
        apr_file_printf(f, "%02x", digest[i]);

    apr_file_printf(f, "\n");
}

static void usage(void)
{
    apr_file_printf(errfile, "Usage: htdigest [-c] passwordfile realm username\n");
    apr_file_printf(errfile, "The -c flag creates a new file.\n");
    exit(1);
}

static void interrupted(void)
{
    apr_file_printf(errfile, "Interrupted.\n");
    cleanup_tempfile_and_exit(1);
}

static void terminate(void)
{
    apr_terminate();
#ifdef NETWARE
    pressanykey();
#endif
}

int main(int argc, const char * const argv[])
{
    apr_file_t *f;
    apr_status_t rv;
    char tn[] = "htdigest.tmp.XXXXXX";
    char *dirname;
    char user[MAX_STRING_LEN];
    char realm[MAX_STRING_LEN];
    char line[MAX_LINE_LEN];
    char l[MAX_LINE_LEN];
    char w[MAX_STRING_LEN];
    char x[MAX_STRING_LEN];
    int found;

    apr_app_initialize(&argc, &argv, NULL);
    atexit(terminate);
    apr_pool_create(&cntxt, NULL);
    apr_file_open_stderr(&errfile, cntxt);

#if APR_CHARSET_EBCDIC
    rv = apr_xlate_open(&to_ascii, "ISO-8859-1", APR_DEFAULT_CHARSET, cntxt);
    if (rv) {
        apr_file_printf(errfile, "apr_xlate_open(): %pm (%d)\n",
                &rv, rv);
        exit(1);
    }
#endif

    apr_signal(SIGINT, (void (*)(int)) interrupted);
    if (argc == 5) {
        if (strcmp(argv[1], "-c"))
            usage();
        rv = apr_file_open(&f, argv[2], APR_WRITE | APR_CREATE,
                           APR_OS_DEFAULT, cntxt);
        if (rv != APR_SUCCESS) {
            apr_file_printf(errfile, "Could not open passwd file %s for writing: %pm\n",
                    argv[2], &rv);
            exit(1);
        }
        apr_cpystrn(user, argv[4], sizeof(user));
        apr_cpystrn(realm, argv[3], sizeof(realm));
        apr_file_printf(errfile, "Adding password for %s in realm %s.\n",
                    user, realm);
        add_password(user, realm, f);
        apr_file_close(f);
        exit(0);
    }
    else if (argc != 4)
        usage();

    if (apr_temp_dir_get((const char**)&dirname, cntxt) != APR_SUCCESS) {
        apr_file_printf(errfile, "%s: could not determine temp dir\n",
                        argv[0]);
        exit(1);
    }
    dirname = apr_psprintf(cntxt, "%s/%s", dirname, tn);

    if (apr_file_mktemp(&tfp, dirname, 0, cntxt) != APR_SUCCESS) {
        apr_file_printf(errfile, "Could not open temp file %s.\n", dirname);
        exit(1);
    }

    if (apr_file_open(&f, argv[1], APR_READ, APR_OS_DEFAULT, cntxt) != APR_SUCCESS) {
        apr_file_printf(errfile,
                "Could not open passwd file %s for reading.\n", argv[1]);
        apr_file_printf(errfile, "Use -c option to create new one.\n");
        cleanup_tempfile_and_exit(1);
    }
/* H. Takeda:
 * コマンドライン引数 user / realm を
 * UTF-8 変換 + NFC 正規化してから内部表現にする
 */
    char *norm_user  = convert_and_normalize_utf8(argv[3]);
    char *norm_realm = convert_and_normalize_utf8(argv[2]);
    if (!norm_user || !norm_realm) {
    apr_file_printf(errfile, "Invalid UTF-8 input\n");
    exit(1);
}
    apr_cpystrn(user,  norm_user,  sizeof(user));
    apr_cpystrn(realm, norm_realm, sizeof(realm));

    free(norm_user);
    free(norm_realm);
    found = 0;
    while (!(get_line(line, sizeof(line), f))) {
        if (found || (line[0] == '#') || (!line[0])) {
            putline(tfp, line);
            continue;
        }
        strcpy(l, line);
        if (getword(w, l, ':') || getword(x, l, ':')) {
            apr_file_printf(errfile, "The following line contains a string longer than the "
                                     "allowed maximum size (%i): %s\n", MAX_STRING_LEN - 1, line);
            cleanup_tempfile_and_exit(1);
        }
        if (strcmp(user, w) || strcmp(realm, x)) {
            putline(tfp, line);
            continue;
        }
        else {
            apr_file_printf(errfile, "Changing password for user %s in realm %s\n",
                    user, realm);
            add_password(user, realm, tfp);
            found = 1;
        }
    }
    if (!found) {
        apr_file_printf(errfile, "Adding user %s in realm %s\n", user, realm);
        add_password(user, realm, tfp);
    }
    apr_file_close(f);

    /* The temporary file has all the data, just copy it to the new location.
     */
    if (apr_file_copy(dirname, argv[1], APR_OS_DEFAULT, cntxt) !=
                APR_SUCCESS) {
        apr_file_printf(errfile, "%s: unable to update file %s\n",
                        argv[0], argv[1]);
    }
    apr_file_close(tfp);

    return 0;
}
