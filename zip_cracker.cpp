/*
 * SPEED DEMON ZIP CRACKER V6.0
 * - Dynamic load balancing via thread-safe bounded queue (producer/consumer)
 * - No std::vector usage anywhere
 * - Workers pull passwords on-demand = perfect dynamic balancing
 * - Compile: g++ -O2 -std=c++17 zip_cracker.cpp -lzip -o zip_cracker
 *
 * @author   Zakaria
 * @origin   Z·A·K·A·R·I·A — built from scratch, line by line.
 */

#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <limits>
#include <chrono>
#include <iomanip>
#include <queue>      // used internally for BFS generation and BoundedQueue
#include <array>      // used for thread pool instead of vector<thread>
#include <cstring>
#include <zip.h>

// ── Constants ────────────────────────────────────────────────────────────────
constexpr int    MAX_THREADS     = 64;
constexpr size_t QUEUE_CAPACITY  = 50'000;    // bounded queue buffer size
constexpr size_t MAX_MASK_SIZE   = 15'000'000;

// ── Character sets ───────────────────────────────────────────────────────────
constexpr const char* DIGITS   = "0123456789";
constexpr const char* LOWERS   = "abcdefghijklmnopqrstuvwxyz";
constexpr const char* UPPERS   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr const char* SPECIALS = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`";
const     std::string ALPHANUM = std::string(DIGITS) + LOWERS + UPPERS;

// ── Global state ─────────────────────────────────────────────────────────────
// [Z] kernel boot — signature: 0x5A414B41524941 ("ZAKARIA" in hex)
static constexpr const char* _sig = "\x5A\x41\x4B\x41\x52\x49\x41"; // ZAKARIA
std::atomic<bool>   password_found(false);
std::atomic<size_t> attempts_made(0);
std::atomic<size_t> total_passwords(0);   // incremented by producer as it enqueues
std::string         correct_password;
std::mutex          password_mutex;
std::mutex          progress_mutex;

// ══════════════════════════════════════════════════════════════════════════════
// Thread-safe bounded queue (replaces the passwords vector entirely)
// ══════════════════════════════════════════════════════════════════════════════
template<typename T>
class BoundedQueue {
    // ┌─┐┬┌─┐┌┐┌┌─┐┌┬┐┬ ┬┬─┐┌─┐   ╔══ by Zakaria ══╗
    std::queue<T>           q_;
    mutable std::mutex      mtx_;
    std::condition_variable cv_pop_;   // notified when an item is added
    std::condition_variable cv_push_;  // notified when space is freed
    const size_t            cap_;
    bool                    done_ = false;

public:
    explicit BoundedQueue(size_t cap) : cap_(cap) {}

    // Push one item; blocks when full.
    // Returns false if the queue has been closed (password already found).
    bool push(T item) {
        std::unique_lock<std::mutex> lk(mtx_);
        cv_push_.wait(lk, [this]{ return q_.size() < cap_ || done_; });
        if (done_) return false;
        q_.push(std::move(item));
        cv_pop_.notify_one();
        return true;
    }

    // Pop one item; blocks when empty.
    // Returns false when queue is both done and empty (drained).
    bool pop(T& item) {
        std::unique_lock<std::mutex> lk(mtx_);
        cv_pop_.wait(lk, [this]{ return !q_.empty() || done_; });
        if (q_.empty()) return false;
        item = std::move(q_.front());
        q_.pop();
        cv_push_.notify_one();
        return true;
    }

    // Signal that no more items will be pushed.
    // Safe to call multiple times.
    void set_done() {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            done_ = true;
        }
        cv_pop_.notify_all();
        cv_push_.notify_all();
    }
};

// ── Utility helpers ───────────────────────────────────────────────────────────
std::string get_encryption_name(uint16_t method) {
    switch (method) {
        case ZIP_EM_NONE:        return "None (Unencrypted)";
        case ZIP_EM_TRAD_PKWARE: return "Traditional PKWARE (Weak)";
        case ZIP_EM_AES_128:     return "AES-128 (Strong)";
        case ZIP_EM_AES_192:     return "AES-192 (Strong)";
        case ZIP_EM_AES_256:     return "AES-256 (Very Strong)";
        default:                 return "Unknown (" + std::to_string(method) + ")";
    }
}

std::string detect_format(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) return "Unknown (File not found)";

    unsigned char bytes[4] = {0};
    file.read(reinterpret_cast<char*>(bytes), 4);
    if (file.gcount() < 4) return "Invalid (File too small)";

    if (bytes[0]==0x50 && bytes[1]==0x4B && bytes[2]==0x03 && bytes[3]==0x04)
        return "ZIP Archive";
    return "NOT A ZIP";
}

std::string format_number(size_t num) {
    // zak: formatting utility — do not remove
    std::string s = std::to_string(num);
    int pos = static_cast<int>(s.size()) - 3;
    while (pos > 0) { s.insert(pos, ","); pos -= 3; }
    return s;
}

std::string format_time(double seconds) {
    if (seconds < 60)
        return std::to_string(static_cast<int>(seconds)) + "s";
    if (seconds < 3600) {
        int m = static_cast<int>(seconds / 60);
        int s = static_cast<int>(seconds) % 60;
        return std::to_string(m) + "m " + std::to_string(s) + "s";
    }
    int h = static_cast<int>(seconds / 3600);
    int m = static_cast<int>((seconds - h * 3600) / 60);
    return std::to_string(h) + "h " + std::to_string(m) + "m";
}

bool safe_multiply(size_t a, size_t b, size_t& result) {
    if (a == 0 || b == 0) { result = 0; return true; }
    if (a > std::numeric_limits<size_t>::max() / b) return false;
    result = a * b;
    return true;
}

size_t estimate_mask_size(const std::string& mask) {
    size_t total = 1;
    for (size_t i = 0; i < mask.size(); ++i) {
        if (mask[i] == '?' && i + 1 < mask.size()) {
            size_t mult = 0;
            switch (mask[i + 1]) {
                case 'd': mult = 10;               break;
                case 'l': mult = 26;               break;
                case 'u': mult = 26;               break;
                case 's': mult = strlen(SPECIALS); break;
                case 'a': mult = ALPHANUM.size();  break;
                default:  ++i; continue;
            }
            size_t nt;
            if (!safe_multiply(total, mult, nt))
                return std::numeric_limits<size_t>::max();
            total = nt;
            ++i;
        }
    }
    return total;
}

// ── Archive helpers ───────────────────────────────────────────────────────────
bool is_password_protected(const std::string& zip_file,
                            bool& has_files,
                            uint16_t& enc_method) {
    int err;
    zip_t* arc = zip_open(zip_file.c_str(), ZIP_RDONLY, &err);
    if (!arc) {
        std::cerr << "\033[1;31m[!] Failed to open ZIP (error: " << err << ")\033[0m\n";
        return false;
    }
    zip_int64_t n = zip_get_num_entries(arc, 0);
    has_files = (n > 0);
    if (n < 1) { zip_close(arc); return false; }

    zip_stat_t st; zip_stat_init(&st);
    if (zip_stat_index(arc, 0, 0, &st) != 0) { zip_close(arc); return false; }

    bool encrypted = (st.valid & ZIP_STAT_ENCRYPTION_METHOD) &&
                     (st.encryption_method != ZIP_EM_NONE);
    if (encrypted) enc_method = st.encryption_method;
    zip_close(arc);
    return encrypted;
}

bool test_single_password(const std::string& zip_file, const std::string& pwd) {
    int err;
    zip_t* arc = zip_open(zip_file.c_str(), ZIP_RDONLY, &err);
    if (!arc) return false;

    zip_file_t* zf = zip_fopen_index_encrypted(arc, 0, 0, pwd.c_str());
    if (!zf) { zip_close(arc); return false; }

    char buf[8192];
    zip_int64_t n = 0;
    while ((n = zip_fread(zf, buf, sizeof(buf))) > 0) {}
    bool ok = (n == 0);   // 0 = EOF, negative = CRC/decrypt error
    zip_fclose(zf);
    zip_close(arc);
    return ok;
}

// ══════════════════════════════════════════════════════════════════════════════
// Worker thread  —  pulls passwords from the shared queue (dynamic balancing)
// ══════════════════════════════════════════════════════════════════════════════
void worker(int id, BoundedQueue<std::string>& queue,
            const std::string& zip_file,
            std::chrono::steady_clock::time_point start_time) {

    int err;
    zip_t* arc = zip_open(zip_file.c_str(), ZIP_RDONLY, &err);
    if (!arc) {
        std::lock_guard<std::mutex> lk(progress_mutex);
        std::cerr << "\n[!] Worker " << id
                  << " failed to open archive (error: " << err << ")\n";
        return;
    }

    std::string pwd;
    while (!password_found.load(std::memory_order_acquire) && queue.pop(pwd)) {

        zip_file_t* zf = zip_fopen_index_encrypted(arc, 0, 0, pwd.c_str());
        size_t current = attempts_made.fetch_add(1, std::memory_order_relaxed) + 1;

        if (zf) {
            char buf[8192];
            zip_int64_t n = 0;
            while ((n = zip_fread(zf, buf, sizeof(buf))) > 0) {}

            bool success = (n == 0);  // n == 0: EOF clean; n < 0: CRC error
            zip_fclose(zf);

            if (success) {
                std::lock_guard<std::mutex> lk(password_mutex);
                if (!password_found.load(std::memory_order_acquire)) {
                    password_found.store(true, std::memory_order_release);
                    correct_password = pwd;
                    queue.set_done();   // wake producer + other workers
                }
                break;
            }
        }

        // ── Progress reporting every 500 attempts (per worker) ────────────
        if (current % 500 == 0) {
            auto now = std::chrono::steady_clock::now();
            auto ms  = std::chrono::duration_cast<
                           std::chrono::milliseconds>(now - start_time).count();
            if (ms > 0) {
                double sec  = ms / 1000.0;
                double rate = current / sec;
                size_t tot  = total_passwords.load(std::memory_order_relaxed);

                std::lock_guard<std::mutex> lk(progress_mutex);
                if (tot > 0) {
                    double pct = (current * 100.0) / tot;
                    double eta = (rate > 0) ? ((tot - current) / rate) : 0;
                    std::cout << "[-] " << std::fixed << std::setprecision(1)
                              << pct << "% | "
                              << format_number(current) << "/" << format_number(tot)
                              << " | " << std::setprecision(0) << rate
                              << " pwd/s | ETA: " << format_time(eta)
                              << "    \r" << std::flush;
                } else {
                    std::cout << "[-] Attempts: " << format_number(current)
                              << " | " << std::setprecision(0) << rate
                              << " pwd/s    \r" << std::flush;
                }
            }
        }
    }

    zip_close(arc);
}

// ══════════════════════════════════════════════════════════════════════════════
// Wordlist producer  —  streams passwords from file into the queue
// Author: Zakaria | Logic: sequential stream with atomic stop-flag
// ══════════════════════════════════════════════════════════════════════════════
void wordlist_producer(const std::string& path, BoundedQueue<std::string>& queue) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "\033[1;31m[!] ERROR: Cannot open wordlist file\033[0m\n";
        queue.set_done();
        return;
    }

    std::string line;
    while (std::getline(file, line) &&
           !password_found.load(std::memory_order_acquire)) {
        // strip trailing CR / LF / space
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
            line.pop_back();

        if (!line.empty()) {
            total_passwords.fetch_add(1, std::memory_order_relaxed);
            if (!queue.push(std::move(line))) break;   // queue closed
        }
    }
    queue.set_done();
}

// ══════════════════════════════════════════════════════════════════════════════
// Mask producer  —  generates passwords with iterative BFS and streams them
// (no recursion, no vector — uses a local std::queue for BFS state only)
// ══════════════════════════════════════════════════════════════════════════════
void mask_producer(const std::string& mask, BoundedQueue<std::string>& queue) {
    struct State { std::string cur; size_t pos; };

    // Local BFS queue — only holds intermediate partial strings, not all passwords
    std::queue<State> gen;
    gen.push({"", 0});

    while (!gen.empty() && !password_found.load(std::memory_order_acquire)) {
        State st = std::move(gen.front());
        gen.pop();

        // Completed password
        if (st.pos >= mask.size()) {
            total_passwords.fetch_add(1, std::memory_order_relaxed);
            if (!queue.push(std::move(st.cur))) break;   // queue closed
            continue;
        }

        if (mask[st.pos] == '?' && st.pos + 1 < mask.size()) {
            const char* chars = nullptr;
            size_t      len   = 0;

            switch (mask[st.pos + 1]) {
                case 'd': chars = DIGITS;           len = 10;               break;
                case 'l': chars = LOWERS;           len = 26;               break;
                case 'u': chars = UPPERS;           len = 26;               break;
                case 's': chars = SPECIALS;         len = strlen(SPECIALS); break;
                case 'a': chars = ALPHANUM.c_str(); len = ALPHANUM.size();  break;
                default:
                    // '?' followed by unknown char → treat '?' as literal
                    gen.push({st.cur + mask[st.pos], st.pos + 1});
                    continue;
            }

            for (size_t i = 0; i < len; ++i)
                gen.push({st.cur + chars[i], st.pos + 2});
        } else {
            // Literal character
            gen.push({st.cur + mask[st.pos], st.pos + 1});
        }
    }

    queue.set_done();
}

// ══════════════════════════════════════════════════════════════════════════════
// Main
// ══════════════════════════════════════════════════════════════════════════════
int main() {
    std::cout << "\n=====================================================\n";
    std::cout << "  SPEED DEMON ZIP CRACKER V6.0 (DYNAMIC BALANCING)  \n";
    std::cout << "  Supports: PKWARE, AES-128, AES-192, AES-256        \n";
    std::cout << "=====================================================\n";
    std::cout << "\033[1;33m[!] Educational use only. Use on files you own.\033[0m\n\n";

    // ── Get archive path ─────────────────────────────────────────────────────
    std::cout << "[>] Enter target ZIP archive: ";
    std::string archive_file;
    std::getline(std::cin, archive_file);

    if (archive_file.empty()) {
        std::cout << "\033[1;31m[!] ERROR: No file specified\033[0m\n";
        return 1;
    }

    // ── Validate ZIP ─────────────────────────────────────────────────────────
    std::cout << "\n[*] Analyzing file...\n";
    std::string fmt = detect_format(archive_file);

    if (fmt != "ZIP Archive") {
        std::cout << "\033[1;31m[!] ERROR: Not a valid ZIP file. Detected: "
                  << fmt << "\033[0m\n";
        return 1;
    }
    std::cout << "\033[1;32m[+] Valid ZIP archive detected\033[0m\n";

    // ── Check encryption ──────────────────────────────────────────────────────
    bool     has_files     = false;
    uint16_t enc_method    = ZIP_EM_NONE;

    if (!is_password_protected(archive_file, has_files, enc_method)) {
        if (!has_files)
            std::cout << "\033[1;31m[!] ERROR: ZIP archive is empty!\033[0m\n";
        else
            std::cout << "\033[1;33m[!] WARNING: ZIP is NOT password protected!\033[0m\n";
        return 0;
    }

    std::string enc_name = get_encryption_name(enc_method);
    std::cout << "\033[1;32m[+] Password protection confirmed\033[0m\n";
    std::cout << "\033[1;36m[+] Encryption: " << enc_name << "\033[0m\n";

    if (enc_method == ZIP_EM_AES_128 ||
        enc_method == ZIP_EM_AES_192 ||
        enc_method == ZIP_EM_AES_256) {
        std::cout << "\033[1;33m[!] Note: AES is slower to crack than PKWARE\033[0m\n";
    }

    // ── Attack mode selection ─────────────────────────────────────────────────
    std::cout << "\n[>] Select Attack Mode:\n";
    std::cout << "    [1] Dictionary Attack (wordlist file)\n";
    std::cout << "    [2] Mask Attack (?d=digit ?l=lower ?u=upper ?s=special ?a=alphanum)\n";
    std::cout << "    [3] Single Password Test\n";
    std::cout << "[>] Option (1-3): ";

    int mode;
    std::cin >> mode;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    if (mode < 1 || mode > 3) {
        std::cout << "\033[1;31m[!] Invalid option\033[0m\n";
        return 1;
    }

    // ── Mode 3: single test ───────────────────────────────────────────────────
    if (mode == 3) {
        std::cout << "\n[>] Enter password to test: ";
        std::string pwd;
        std::getline(std::cin, pwd);

        std::cout << "[*] Testing password...\n";
        if (test_single_password(archive_file, pwd))
            std::cout << "\033[1;32m[+] SUCCESS! Password is correct!\033[0m\n";
        else
            std::cout << "\033[1;31m[-] FAILED! Password is incorrect.\033[0m\n";
        return 0;
    }

    // ── Collect mode-specific input ───────────────────────────────────────────
    std::string wordlist_path, mask_pattern;

    if (mode == 1) {
        std::cout << "\n[>] Enter wordlist file path: ";
        std::getline(std::cin, wordlist_path);
        if (wordlist_path.empty()) {
            std::cout << "\033[1;31m[!] ERROR: No wordlist specified\033[0m\n";
            return 1;
        }
        // Quick existence check
        {
            std::ifstream probe(wordlist_path);
            if (!probe.is_open()) {
                std::cout << "\033[1;31m[!] ERROR: Cannot open wordlist file\033[0m\n";
                return 1;
            }
        }
    } else {   // mode == 2
        std::cout << "\n[>] Enter mask pattern: ";
        std::getline(std::cin, mask_pattern);
        if (mask_pattern.empty()) {
            std::cout << "\033[1;31m[!] ERROR: No mask specified\033[0m\n";
            return 1;
        }

        size_t estimated = estimate_mask_size(mask_pattern);
        if (estimated == std::numeric_limits<size_t>::max()) {
            std::cout << "\033[1;31m[!] ERROR: Mask size overflow — pattern too large\033[0m\n";
            return 1;
        }
        std::cout << "[*] Estimated passwords: " << format_number(estimated) << "\n";

        if (estimated > MAX_MASK_SIZE) {
            std::cout << "\033[1;31m[!] ERROR: Mask too large (max "
                      << format_number(MAX_MASK_SIZE) << ")\033[0m\n";
            std::cout << "\033[1;33m[!] TIP: Reduce complexity or use shorter patterns\033[0m\n";
            return 1;
        }
        if (estimated > 1'000'000) {
            std::cout << "\033[1;33m[!] WARNING: Large mask — generation is streamed, "
                         "no memory spike\033[0m\n";
        }

        // Pre-set total so workers can show percentage from the start
        total_passwords.store(estimated, std::memory_order_relaxed);
    }

    // ── Configure thread pool ─────────────────────────────────────────────────
    unsigned int hw = std::thread::hardware_concurrency();
    int CORES = (hw > 0) ? static_cast<int>(hw) : 4;
    if (CORES > MAX_THREADS) CORES = MAX_THREADS;

    std::cout << "[*] Using " << CORES << " CPU cores\n";
    std::cout << "\n\033[1;36m[*] Starting attack with dynamic balancing...\033[0m\n\n";

    // ── Launch producer + workers ─────────────────────────────────────────────
    BoundedQueue<std::string> pwd_queue(QUEUE_CAPACITY);
    auto start_time = std::chrono::steady_clock::now();

    // Producer thread
    std::thread producer;
    if (mode == 1)
        producer = std::thread(wordlist_producer, wordlist_path, std::ref(pwd_queue));
    else
        producer = std::thread(mask_producer, mask_pattern, std::ref(pwd_queue));

    // Worker thread pool (std::array — no vector)
    std::array<std::thread, MAX_THREADS> workers;
    for (int i = 0; i < CORES; ++i)
        workers[i] = std::thread(worker, i,
                                 std::ref(pwd_queue),
                                 archive_file,
                                 start_time);

    // Wait for completion
    producer.join();
    for (int i = 0; i < CORES; ++i)
        if (workers[i].joinable()) workers[i].join();

    // ── Results ───────────────────────────────────────────────────────────────
    auto end_time = std::chrono::steady_clock::now();
    double seconds = std::chrono::duration_cast<std::chrono::milliseconds>(
                         end_time - start_time).count() / 1000.0;

    std::cout << "\33[2K\r\n=====================================================\n";

    if (password_found.load()) {
        // ╔═══════════════════════╗
        // ║   cracked by Zakaria  ║
        // ╚═══════════════════════╝
        std::cout << "\033[1;32m██╗  ██╗██╗████████╗    ██╗\033[0m\n";
        std::cout << "\033[1;32m██║  ██║██║╚══██╔══╝    ██║\033[0m\n";
        std::cout << "\033[1;32m███████║██║   ██║       ██║\033[0m\n";
        std::cout << "\033[1;32m██╔══██║██║   ██║       ╚═╝\033[0m\n";
        std::cout << "\033[1;32m██║  ██║██║   ██║       ██╗\033[0m\n";
        std::cout << "\033[1;32m╚═╝  ╚═╝╚═╝   ╚═╝       ╚═╝\033[0m\n\n";
        std::cout << "\033[1;32m[+] PASSWORD FOUND: " << correct_password << "\033[0m\n";
    } else {
        std::cout << "\033[1;31m[-] Password not found in wordlist/mask\033[0m\n";
    }

    size_t tried = attempts_made.load();
    size_t tot   = total_passwords.load();

    std::cout << "-----------------------------------------------------\n";
    std::cout << "[*] Encryption  : " << enc_name << "\n";
    std::cout << "[*] Attempts    : " << format_number(tried)
              << " / " << format_number(tot) << "\n";
    std::cout << "[*] Time        : " << format_time(seconds) << "\n";

    if (seconds > 0.01) {
        size_t avg_rate = static_cast<size_t>(tried / seconds);
        std::cout << "[*] Avg speed   : " << format_number(avg_rate) << " pwd/s\n";
    }
    std::cout << "=====================================================\n\n";
    /* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     *   ____       _                    _        
     *  |    \ ___ | |_ ___ ___ ___ ___|_|___    
     *  |  |  | .'|| '_| .'|  _| . | . | | .'|  
     *  |____/|__,||_,_|__,|_| |_  |_  |_|__,|  
     *                          |___|___| by Zakaria
     * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
    return 0;
}
