/*-
 * @file   src/ext_attester.c
 * @brief  Shared external-attester spawn helper (see src/ext_attester.h).
 *
 * Deliberately free of secutils' LOG(): its basic.h defines its own bool
 * enum, which clashes with the <stdbool.h> the QCBOR headers pull in, and
 * the file-read/fork helpers are needed both there and in cmpClient.c.
 */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE /* close_range, mkostemp */
#endif

#include "ext_attester.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define EXT_ATTESTER_TIMEOUT_S 30

/* Not secutils' LOG(): see the file header. */
#define ERR(...) (fprintf(stderr, "ext_attester: " __VA_ARGS__), fputc('\n', stderr))

/* Fork the helper as its own process group, wait with a timeout, and kill
 * the whole group on expiry so a wedged helper cannot hang the enrolment.
 * Returns 1 iff it exited 0 in time. */
static int spawn_and_wait(const char *cmd, const char *hex, const char *path)
{
    char *argv[] = { (char *)cmd, (char *)hex, (char *)path, NULL };
    struct timespec tick = { 0, 20L * 1000 * 1000 }; /* 20 ms */
    int status = 0, waited_ms = 0;
    pid_t done, pid = fork();

    if (pid < 0) {
        ERR("fork: %s", strerror(errno));
        return 0;
    }
    if (pid == 0) {
        int fd = open("/dev/null", O_RDONLY);

        setpgid(0, 0); /* own group, so a timeout also kills e.g. xclaim */
        if (fd >= 0)
            dup2(fd, 0);
        /* inherit only 0/1/2: no CMP socket, no temp-file descriptor */
        if (close_range(3, ~0U, 0) != 0) {
            long max = sysconf(_SC_OPEN_MAX);
            for (fd = 3; fd < max && fd < 65536; fd++)
                close(fd);
        }
        execv(cmd, argv);
        _exit(127);
    }
    while ((done = waitpid(pid, &status, WNOHANG)) == 0) {
        if (waited_ms >= EXT_ATTESTER_TIMEOUT_S * 1000) {
            ERR("helper timed out after %d s, killing it", EXT_ATTESTER_TIMEOUT_S);
            kill(-pid, SIGKILL);
            waitpid(pid, &status, 0);
            return 0;
        }
        nanosleep(&tick, NULL);
        waited_ms += 20;
    }
    if (done < 0) { /* e.g. SIGCHLD ignored by a parent: never read that as success */
        ERR("waitpid: %s", strerror(errno));
        kill(-pid, SIGKILL);
        return 0;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        ERR("helper failed (status 0x%x)", status);
        return 0;
    }
    return 1;
}

/* Read a regular file of 1..max_len bytes; malloc'd result or NULL. */
static unsigned char *read_small_file(const char *path, size_t *len, size_t max_len)
{
    struct stat st;
    unsigned char *buf = NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t n;

    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)
            || st.st_size <= 0 || st.st_size > (off_t)max_len) {
        ERR("helper output missing, empty or larger than %zu bytes", max_len);
        goto err;
    }
    buf = malloc((size_t)st.st_size);
    if (buf == NULL)
        goto err;
    n = read(fd, buf, (size_t)st.st_size);
    if (n != st.st_size) {
        free(buf);
        buf = NULL;
        goto err;
    }
    *len = (size_t)n;
 err:
    if (fd >= 0)
        close(fd);
    return buf;
}

int ext_attester_run(const char *cmd, const unsigned char *nonce, size_t nonce_len,
                     size_t max_out, char *tmp_template,
                     unsigned char **out, size_t *out_len)
{
    size_t i;
    char *hex;
    unsigned char *buf = NULL;
    size_t len = 0;
    int fd, ok = 0;

    if (out == NULL || out_len == NULL)
        return 0;
    *out = NULL;
    *out_len = 0;
    if (cmd == NULL || cmd[0] != '/') {
        ERR("helper path must be absolute: %s", cmd == NULL ? "(null)" : cmd);
        return 0;
    }
    if (nonce == NULL || nonce_len == 0) {
        ERR("empty nonce");
        return 0;
    }
    hex = malloc(2 * nonce_len + 1);
    if (hex == NULL)
        return 0;
    for (i = 0; i < nonce_len; i++)
        (void)snprintf(hex + 2 * i, 3, "%02x", nonce[i]); /* bounded: 2 hex digits + NUL */

    fd = mkostemp(tmp_template, O_CLOEXEC);
    if (fd < 0) {
        ERR("mkostemp: %s", strerror(errno));
        free(hex);
        return 0;
    }
    close(fd);

    if (spawn_and_wait(cmd, hex, tmp_template))
        buf = read_small_file(tmp_template, &len, max_out);
    free(hex);
    if (buf != NULL) {
        *out = buf;
        *out_len = len;
        buf = NULL;
        ok = 1;
    }
    free(buf);
    (void)unlink(tmp_template);
    return ok;
}
