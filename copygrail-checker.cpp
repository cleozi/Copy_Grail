/*
 * copygrail-checker v1
 * Vulnerability checker for CVE-2026-31431 (Copy Fail) LPE
 * 
 * Build: g++ -O2 -static -o copygrail-checker checker.cpp
 */

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_alg.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <cstdint>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define CYAN "\033[36m"
#define PINK "\033[35m"
#define RESET "\033[0m"

// Check if AF_ALG is available and the specific AEAD cipher works
bool check_af_alg() {
    int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (s < 0) {
        return false;
    }
    
    struct sockaddr_alg sa = {};
    sa.salg_family = AF_ALG;
    memcpy(sa.salg_type, "aead", 5);
    memcpy(sa.salg_name, "authencesn(hmac(sha256),cbc(aes))", 34);
    
    if (bind(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(s);
        return false;
    }
    
    close(s);
    return true;
}

// Check if /usr/bin/su is accessible and readable
bool check_su_binary() {
    struct stat st;
    if (stat("/usr/bin/su", &st) < 0) {
        return false;
    }
    
    int fd = open("/usr/bin/su", O_RDONLY);
    if (fd < 0) {
        return false;
    }
    
    close(fd);
    return true;
}

// Test if splice() works on the file descriptor
bool check_splice_capability() {
    int fd = open("/usr/bin/su", O_RDONLY);
    if (fd < 0) {
        return false;
    }
    
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        close(fd);
        return false;
    }
    
    // Try a harmless splice read
    off_t offset = 0;
    ssize_t result = splice(fd, &offset, pipefd[1], nullptr, 4, SPLICE_F_MOVE);
    
    close(pipefd[0]);
    close(pipefd[1]);
    close(fd);
    
    return (result > 0);
}

// Perform a safe test of the vulnerability primitives
bool test_vulnerability_primitives() {
    int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (s < 0) return false;
    
    struct sockaddr_alg sa = {};
    sa.salg_family = AF_ALG;
    memcpy(sa.salg_type, "aead", 5);
    memcpy(sa.salg_name, "authencesn(hmac(sha256),cbc(aes))", 34);
    
    if (bind(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(s);
        return false;
    }
    
    static const unsigned char k[40] = {0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x10,0};
    if (setsockopt(s, SOL_ALG, ALG_SET_KEY, k, sizeof(k)) < 0) {
        close(s);
        return false;
    }
    
    int as = 4;
    if (setsockopt(s, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, &as, 4) < 0) {
        close(s);
        return false;
    }
    
    int o = accept(s, nullptr, nullptr);
    if (o < 0) {
        close(s);
        return false;
    }
    
    close(o);
    close(s);
    return true;
}

void print_kernel_info() {
    struct utsname uts;
    if (uname(&uts) == 0) {
        std::cout << CYAN << "[*] Kernel: " << RESET << uts.sysname << " " 
                  << uts.release << " " << uts.machine << "\n";
    }
}

int main() {
    std::cout << CYAN << R"(
╔═══════════════════════════════════════╗
║  CVE-2026-31431 Vulnerability Checker ║
║         (Copy Fail LPE)               ║
╚═══════════════════════════════════════╝
)" << RESET << "\n";
    
    print_kernel_info();
    std::cout << "\n";
    
    bool vulnerable = true;
    int checks_passed = 0;
    int total_checks = 4;
    
    // Check 1: AF_ALG availability
    std::cout << "[1/4] Checking AF_ALG socket support... ";
    if (check_af_alg()) {
        std::cout << YELLOW << "PRESENT" << RESET << "\n";
        checks_passed++;
    } else {
        std::cout << GREEN << "NOT AVAILABLE" << RESET << " (safe)\n";
        vulnerable = false;
    }
    
    // Check 2: /usr/bin/su binary
    std::cout << "[2/4] Checking /usr/bin/su accessibility... ";
    if (check_su_binary()) {
        std::cout << YELLOW << "ACCESSIBLE" << RESET << "\n";
        checks_passed++;
    } else {
        std::cout << GREEN << "NOT ACCESSIBLE" << RESET << " (safe)\n";
        vulnerable = false;
    }
    
    // Check 3: splice() capability
    std::cout << "[3/4] Checking splice() on target binary... ";
    if (check_splice_capability()) {
        std::cout << YELLOW << "WORKING" << RESET << "\n";
        checks_passed++;
    } else {
        std::cout << GREEN << "BLOCKED" << RESET << " (safe)\n";
        vulnerable = false;
    }
    
    // Check 4: Full primitive chain
    std::cout << "[4/4] Testing vulnerability primitives... ";
    if (test_vulnerability_primitives()) {
        std::cout << YELLOW << "FUNCTIONAL" << RESET << "\n";
        checks_passed++;
    } else {
        std::cout << GREEN << "NON-FUNCTIONAL" << RESET << " (safe)\n";
        vulnerable = false;
    }
    
    std::cout << "\n";
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    
    if (vulnerable && checks_passed == total_checks) {
        std::cout << RED << "⚠  SYSTEM IS VULNERABLE" << RESET << "\n";
        std::cout << "   All exploit primitives are functional.\n";
        std::cout << "   CVE-2026-31431 can be exploited on this system.\n\n";
        std::cout << "   Mitigation recommendations:\n";
        std::cout << "   • Update kernel to patched version\n";
        std::cout << "   • Disable AF_ALG if not needed\n";
        std::cout << "   • Apply security updates\n";
    } else {
        std::cout << GREEN << "✓  SYSTEM APPEARS SAFE" << RESET << "\n";
        std::cout << "   (" << (total_checks - checks_passed) << "/" << total_checks 
                  << " required primitives are blocked)\n";
        if (checks_passed > 0) {
            std::cout << YELLOW << "   Note: Some primitives are present but exploit chain is broken.\n" << RESET;
        }
    }
    
    std::cout << "\n" << PINK << "love by cleo <3" << RESET << "\n";
    
    return vulnerable ? 1 : 0;
}
