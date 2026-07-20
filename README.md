<div align="center">

```text
    ____ ___  _________  ____  ____ _____
   / __ `__ \/ ___/ __ \/ __ \/ ___/ ___/
  / / / / / / /  / /_/ / /_/ (__  |__  ) 
 /_/ /_/ /_/_/  / .___/\__,_/____/____/  
               /_/                       
```

### 🚀 Advanced OSINT & Security Analysis Tool v3.2.1

**A high-performance CLI security analysis tool engineered for Penetration Testers and Security Analysts.**

</div>

---

## 📌 About `mrpass`

`mrpass` is an advanced, standalone command-line interface tool designed to streamline security assessments, credential auditing, and target intelligence gathering. Built with a heavy focus on speed, clean terminal formatting, and system-wide integration.

---

## ⚙️ Key Features

- **Advanced Password Entropy & Strength Analyzer:** Evaluates character complexity, calculates entropy bits, and estimates brute-force crack time.
- **OSINT Breach Intelligence:** Integrated with HaveIBeenPwned (HIBP) API and XposedOrNot (XON) for instant credential leak detection.
- **Phone Number OSINT Analysis:** Identifies carrier, country, timezone, and auto-generates custom Google Dorks for deep digital footprinting.
- **Email Intelligence:** Checks for corporate/personal breaches and detects disposable (burner) email providers.
- **Hash Type Identifier:** Automatically recognizes MD5, SHA families, NTLM, and Unix crypt hashes.
- **Pentest Wordlist Mutator:** Generates high-probability brute-force mutations (leet-speak variations, standard suffixes, and current-year patterns) from a base target word.
- **System-Wide Installation:** Installs globally via a single setup script so you can run it instantly from anywhere like standard security tools (`nmap`, `john`).
- **Professional Reporting:** Supports bulk file scanning and clean CSV export formatting.

---

## 📥 Installation & Setup

`mrpass` comes with an automated installation script (`install.sh`) that installs all required dependencies and sets up the tool globally in your system path.

### 1. Clone the Repository

```bash
git clone https://github.com/mahmoudramadan06/mrpass.git
cd mrpass
```

### 2. Run the Installer

Run the installation script with root privileges to configure the dependencies and make `mrpass` available globally:

```bash
sudo chmod +x install.sh
sudo ./install.sh
```

### 3. Run the Tool

Once the installation is complete, you can run the tool from anywhere in your terminal without typing python or file extensions:

```bash
mrpass -h
```

---

## 🛠️ Syntax & Usage Guide

```text
mrpass [TARGET] [OPTIONS]
```

### Target Modes

| Flag | Description |
|---|---|
| `-ps`, `--password` | Analyze password strength, entropy, and crack time |
| `-em`, `--email` | Investigate email addresses for breaches and disposable status |
| `-ph`, `--phone` | Analyze phone numbers (Carrier, Country, OSINT Dorks) |
| `-id`, `--identify` | Identify unknown hash types (MD5, SHA, NTLM, etc.) |
| `-m`, `--mutate [FILE]` | Generate a custom pentest wordlist from a base target word |
| `-n`, `--new [LENGTH]` | Generate a secure random password (default length: 16) |

### OSINT & File Operations

| Flag | Description |
|---|---|
| `-sr`, `--search-leak` | Query threat intel APIs (HaveIBeenPwned, XposedOrNot, Debounce) |
| `-f`, `--file [FILE]` | Bulk scan mode: Read multiple targets from a text file |
| `-o`, `--output [FILE]` | Export all scan results to a formatted CSV file |
| `-q`, `--quiet` | Stealth/Automation mode: Suppress banners and UI formatting |
| `-h`, `--help` | Show advanced help menu |

---

## 💡 Real-World Examples

**1. OSINT Password Audit (with online breach check):**
```bash
mrpass "Admin@123" -ps -sr
```

**2. Email Threat Intelligence & Breach Check:**
```bash
mrpass "target@mail.com" -em -sr
```

**3. Phone Number OSINT & Dorking:**
```bash
mrpass "+201093792767" -ph
```

**4. Identify Unknown Hash Type:**
```bash
mrpass "5d41402abc4b2a76b9719d911017c592" -id
```

**5. Generate a Secure Random Password (20 chars):**
```bash
mrpass -n 20
```

**6. Bulk Scan from File & Export to CSV Report:**
```bash
mrpass -f targets.txt -ps -sr -o audit_report.csv
```

**7. View Developer & Tool Information:**
```bash
mrpass info
```

---

## 👨‍💻 Author & Developer

- **Name:** Mahmoud Ramadan Elbezzawy
- **Field:** Computer Science & Artificial Intelligence (Cybersecurity Focus)
- **GitHub:** [github.com/mahmoudramadan06](https://github.com/mahmoudramadan06)
- **LinkedIn:** [linkedin.com/in/mahmoud-r-elbezzawy](https://www.linkedin.com/in/mahmoud-r-elbezzawy)

---

## 📝 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
