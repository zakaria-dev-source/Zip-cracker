🔐 Speed Demon ZIP Cracker V6.0
High-performance, multi-threaded ZIP password recovery tool written in modern C++17.
Built with dynamic load balancing and zero std::vector usage.



✨ Features
⚡ Dynamic Load Balancing — thread-safe bounded queue (producer/consumer pattern)
🧵 Multi-threaded — auto-detects CPU cores, supports up to 64 threads
🔑 3 Attack Modes — Dictionary, Mask, and Single Password Test
🛡️ Full Encryption Support — PKWARE, AES-128, AES-192, AES-256
📊 Live Progress — real-time speed, ETA, and percentage display
🧠 Memory Efficient — passwords streamed on-demand, no bulk loading
🚫 No std::vector — uses std::array + std::queue throughout



🛠️ Requirements
Dependency
Version
C++ Compiler
C++17 or later
libzip
≥ 1.0
POSIX Threads
standard
Install libzip
# Ubuntu / Debian
sudo apt install libzip-dev

# macOS (Homebrew)
brew install libzip

# Arch Linux
sudo pacman -S libzip



🚀 Build
g++ -O2 -std=c++17 zip_cracker.cpp -lzip -o zip_cracker



📖 Usage
./zip_cracker
Then follow the interactive prompts:
[>] Enter target ZIP archive: secret.zip
[>] Select Attack Mode:
    [1] Dictionary Attack (wordlist file)
    [2] Mask Attack (?d=digit ?l=lower ?u=upper ?s=special ?a=alphanum)
    [3] Single Password Test
�


🎭 Attack Modes
1️⃣ Dictionary Attack
Tries every password from a wordlist file (e.g. rockyou.txt).
[>] Option: 1
[>] Enter wordlist file path: /usr/share/wordlists/rockyou.txt

2️⃣ Mask Attack
Generates passwords based on a pattern using wildcard tokens:
Token
Meaning
Characters
?d
Digit
0-9
?l
Lowercase
a-z
?u
Uppercase
A-Z
?s
Special chars
!@#$...
?a
Alphanumeric
0-9a-zA-Z
Examples:
?d?d?d?d          # 4-digit PIN (0000–9999)
?l?l?l?d?d        # 3 lowercase letters + 2 digits
admin?d?d?d       # "admin" followed by 3 digits
?u?l?l?l?d?s      # complex pattern

3️⃣ Single Password Test
Quickly tests one specific password against the ZIP file.




📐 Architecture
┌─────────────────────────────────────────────────────┐
│                    Main Thread                       │
│         (validates ZIP, configures workers)          │
└───────────────────┬─────────────────────────────────┘
                    │
          ┌─────────▼──────────┐
          │  Producer Thread   │  ← streams wordlist / generates mask
          │  (wordlist/mask)   │
          └─────────┬──────────┘
                    │ BoundedQueue<string> (50,000 cap)
        ┌───────────▼───────────────┐
        │   Worker Thread Pool      │
        │  [T0][T1][T2]...[Tn]      │  ← N = hardware_concurrency()
        │  each pulls & tests pwd   │
        └───────────────────────────┘



⚠️ Legal Disclaimer
This tool is intended for educational purposes only.
Only use it on ZIP files you own or have explicit permission to test.
Unauthorized access to password-protected files may be illegal in your jurisdiction.



👤 Author
Zakaria
Built from scratch — engineered for speed.






📄 License
This project is open source. Use responsibly.
