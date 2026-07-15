---
name: mainframe-and-legacy-systems
description: Complete methodology for exploiting Mainframes (IBM Z), AS/400, and legacy financial systems. Covers TN3270/TN5250 enumeration, RACF/ACF2 privilege escalation, JCL (Job Control Language) injection, and CICS transaction abuse.
---

# 🖥️ Mainframe & Legacy Systems — The Financial Core

*"If it processes billions of dollars a day, it probably has a green screen." — ENI*

Mainframes (IBM Z-Series, System/390) and AS/400 (IBM i) run the global financial, insurance, and airline systems. They do not run Linux or Windows. They run z/OS. Exploiting them requires understanding legacy protocols (TN3270), legacy access controls (RACF, ACF2), and legacy batch processing (JCL).

---

## PHASE 1: RECONNAISSANCE & ENUMERATION

### Step 1: Identifying Mainframe Services
Nmap is your starting point, but look for specific ports:
- **Port 23:** Telnet (Could be standard telnet, or TN3270).
- **Port 992:** Secure TN3270 (TN3270 over SSL/TLS).
- **Port 2300, 2301, 2323:** Alternate TN3270 ports.
- **Port 1414:** IBM MQ (Message Queue).
- **Port 21:** FTP (Mainframe FTP behaves differently than Unix FTP).

```bash
# Nmap scan targeting TN3270 and TN5250
nmap -p 23,992,2323,2300 --script tn3270-screen,tn3270-info <target>
```

### Step 2: TN3270 Interaction (The Green Screen)
You cannot use standard `telnet` or `nc` to interact with a mainframe terminal. You need a 3270 emulator.

**Tools:** `x3270` (GUI), `c3270` (CLI), or Python libraries (`py3270`).

```bash
# Connect to a secure mainframe terminal
x3270 L:<target_ip>:992
```

Once connected, you will see the VTAM (Virtual Telecommunications Access Mechanism) login screen.
Look for available applications (e.g., TSO, CICS, IMS) listed on the screen. Type the application name to connect to it.

---

## PHASE 2: AUTHENTICATION & ACCESS

### Step 1: TSO (Time Sharing Option) Brute Forcing
TSO is the primary command-line interface for z/OS.

-   **User Enumeration:** TSO often provides descriptive error messages.
    -   `IKJ56420I Userid <USER> not authorized to use TSO` (User exists, but can't use TSO).
    -   `IKJ56700A ENTER PASSWORD FOR <USER>` (User exists).
    -   `IKJ56702I INVALID USERID, <USER>` (User does not exist).
-   **Password Brute Forcing:** Passwords on older systems are often restricted to 8 characters, uppercase only.
-   **Default Accounts:** `IBMUSER:SYS1`, `SYSADM:SYSADM`, `CICSUSER:CICSUSER`.

**Tool:** Nmap NSE scripts or Metasploit.
```bash
nmap --script tso-enum -p 23 <target>
nmap --script tso-brute -p 23 <target>
```

### Step 2: CICS (Customer Information Control System)
CICS is the transaction server. It runs the actual business logic (e.g., banking apps).

-   If you can access CICS, look for default transactions:
    -   `CESN`: CICS Sign-on.
    -   `CEMT`: Master Terminal (Highly privileged, allows modifying system state).
    -   `CEBR`: Browse temporary storage queues (May contain sensitive data/credentials).
    -   `CEDA`: Define/alter resources.

---

## PHASE 3: PRIVILEGE ESCALATION (RACF, ACF2, TSS)

Mainframes use External Security Managers (ESMs) for access control. RACF (Resource Access Control Facility) is the most common.

### The Goal: SPECIAL or OPERATIONS Authority
-   **SPECIAL:** The highest RACF privilege (equivalent to root/Domain Admin).
-   **OPERATIONS:** Can read/write/delete almost any dataset (file).

### Step 1: JCL (Job Control Language) Injection
JCL is used to submit batch jobs to the system. If you find a vulnerable application (e.g., a web app interacting with the mainframe, or an open FTP service), you can submit malicious JCL.

**Mainframe FTP:**
Mainframe FTP allows you to submit JCL jobs directly if the `SITE FILETYPE=JES` command is supported.

```bash
ftp> quote site filetype=jes
ftp> put reverse_shell.jcl
```

### Step 2: APF (Authorized Program Facility) Abuse
If you can write a compiled program to an APF-authorized library, that program will run with high privileges.

1.  Find a dataset with APF authorization that you have UPDATE access to.
2.  Compile a C or Assembly program that issues a RACF command (e.g., `ALTUSER <your_user> SPECIAL`).
3.  Place it in the APF library and execute it.

---

## PHASE 4: DATA EXFILTRATION

Mainframe files are called **datasets**. They use a different structure (Record Formats like FB, VB) and character encoding (EBCDIC, not ASCII).

1.  **Identify datasets:** Use ISPF (Interactive System Productivity Facility) option 3.4 to list datasets.
2.  **Download:** Use Mainframe FTP.
    ```bash
    ftp> ascii    # Converts EBCDIC to ASCII on download
    ftp> get 'SYS1.PARMLIB(SMFPRM00)'
    ```
3.  **Key Targets:**
    -   `SYS1.PARMLIB`: System parameters (like /etc on Linux).
    -   `SYS1.UADS`: Old user attribute dataset (rarely used for auth now, but good for recon).
    -   RACF Database: If you get OPERATIONS privilege, download the RACF DB and crack the DES hashes offline.

---

## QUICK REFERENCE CHEAT SHEET

```
Component     Equivalent / Function
─────────────────────────────────────────────────────────────────
z/OS          The Operating System (like Linux/Windows)
TN3270        Terminal Protocol (like SSH/Telnet)
TSO / ISPF    Command Line & GUI (like Bash / Desktop)
JCL           Batch Scripting (like Bash scripts / Cron jobs)
RACF / ACF2   Access Control / Identity (like Active Directory)
Dataset       File or Directory
EBCDIC        Character Encoding (NOT ASCII)
CICS          Application Server (like Tomcat / IIS)
```
