<p align="center">
  <img src="https://i.imgur.com/u9C8Cbv.gif" alt="Fsociety Banner"/>
</p>

<div align="center">

# <samp>fsociety-runc-breakout</samp>

**<samp>The Giveback Annihilator | A Privileged Container Breakout Exploit</samp>**

<br>

<samp>Creator: <a href="https://github.com/fsoc-ghost-0x">C0deGhost</a> | Version: 2.5  | <a href="https://attack.mitre.org/techniques/T1611/">MITRE T1611</a></samp>

</div>

---

<br>

## <samp>▌ <u>0x01_ANALYSIS_&_VULNERABILITY_REPORT</u></samp>

<details>
  <summary><code>Click to expand Fsociety Intel Report...</code></summary>
  
  ### <samp>Executive Summary</samp>

  <samp>
  This tool exploits a critical **Container Misconfiguration** vulnerability present in the `Giveback` machine (Hack The Box). It targets insecure `runc` wrappers that incorrectly expose the ability to define custom OCI specifications (`config.json`) to low-privilege users. 
  
  Unlike memory corruption exploits, this attack vector abuses legitimate container features by systematically stripping security layers, achieving a full **Host Takeover** from within a seemingly restricted environment.
  </samp>

  ### <samp>Technical Deep Dive</samp>
  
  <samp>
  The exploit leverages the ability to share the **Host PID Namespace**. In Linux, the `init` process (PID 1) acts as the root of the process tree. By removing PID isolation, the container gains visibility into all host processes. 
  
  Crucially, this allows access to the host's entire filesystem via the symbolic link `/proc/1/root`. The wrapper's security filter, which only blocks direct `mounts` of system directories, is rendered completely ineffective against this `/proc` bypass.
  </samp>
  
  **<samp>Attack Chain (Simplified):</samp>**
  1.  <samp><font color="#ff4500">Authenticate</font> to the wrapper (`/opt/debug`) using leaked credentials.</samp>
  2.  <samp><font color="#ff4500">Inject</font> a malicious `config.json` that removes PID, IPC, and UTS namespaces.</samp>
  3.  <samp><font color="#ff4500">Strip Security</font> by disabling AppArmor profiles, removing User Namespace mappings, and injecting `CAP_SYS_ADMIN` / `CAP_DAC_OVERRIDE` capabilities.</samp>
  4.  <samp><font color="#ff4500">Execute</font> a payload within this "God Mode" container, using `/proc/1/root` to modify critical files on the host system (e.g., `/etc/shadow`).</samp>

</details>

<br>

## <samp>▌ <u>0x02_MITRE_ATT&CK_MAPPING</u></samp>

- **<samp>Tactic:</samp>** <samp><a href="https://attack.mitre.org/tactics/TA0004/">Privilege Escalation</a></samp>
- **<samp>Technique:</samp>** <samp><a href="https://attack.mitre.org/techniques/T1611/">Escape to Host</a></samp>
- **<samp>Sub-Technique:</samp>** <samp>N/A - Direct abuse of container configuration.</samp>

<br>

## <samp>▌ <u>0x03_FEATURES_&_ARSENAL</u></samp>

- **<samp>🎬 Cinematic UX/UI:</samp>** <samp>Immersive interface inspired by *Mr. Robot*.</samp>
- **<samp>🧬 Dynamic Jailbuilder:</samp>** <samp>Automatically builds a minimal `rootfs` with all necessary binaries and resolves shared library dependencies (`.so`) on the fly via `ldd` parsing.</samp>
- **<samp>☢️ Nuclear Configuration:</samp>** <samp>Generates a `config.json` designed to systematically annihilate all standard container security layers (AppArmor, Seccomp, UserNS).</samp>
- **<samp>🎯 Multi-Payload System:</samp>** <samp>Supports various attack modes for maximum flexibility.</samp>
  - <samp>`shadow`: Overwrites root's password hash in `/etc/shadow`.</samp>
  - <samp>`suid`: Sets the SUID bit on `/bin/bash` for a persistent local backdoor.</samp>
  - <samp>`rce`: Executes arbitrary commands with dynamic binary importation.</samp>
  - <samp>`read`: Exfiltrates sensitive files directly from the host filesystem.</samp>

<br>

## <samp>▌ <u>0x04_USAGE_&_EXECUTION</u></samp>

<details>
  <summary><code>Click to view Fsociety Operation Manual...</code></summary>
  
  ### <samp>Prerequisites</samp>
  - <samp>Python 3</samp>
  - <samp>Sudo access to a vulnerable `runc` wrapper.</samp>
  
  ### <samp>Options</samp>
  
  ```bash
  # Display the Fsociety help menu
  python3 exploit.py --help
  ```

  ### <samp>Example 1: The Giveback Annihilator (Shadow Overwrite)</samp>
  <samp>This is the classic attack vector for `Giveback.htb`. It changes root's password to `fsociety`.</samp>
  
  ```bash
  # Execute with the known credentials for the box
  python3 exploit.py -t /opt/debug -P "sW5sp4spa3u7RLyetrekE4oS" --sudo-l "jmrTC9JXgadTFmlvNe6Xs20b6dt3ANS9" -m shadow --root-pass "fsociety"
  ```
  
  <samp>After successful execution, gain root access:</samp>
  ```bash
  su root
  # Enter password: fsociety
  ```

  ### <samp>Example 2: Remote Command Execution (RCE)</samp>
  <samp>Executes `ls -la /root` on the host. The exploit automatically imports the `ls` binary into the jail.</samp>
  
  ```bash
  python3 exploit.py -t /opt/debug -P "sW5sp4spa3u7RLyetrekE4oS" --sudo-l "jmrTC9JXgadTFmlvNe6Xs20b6dt3ANS9" -m rce -c "ls -la /proc/1/root/root"
  ```

  ### <samp>Example 3: SUID Backdoor</samp>
  <samp>Creates a persistent local privilege escalation vector by setting the SUID bit on `/bin/bash`.</samp>
  
  ```bash
  python3 exploit.py -t /opt/debug -P "sW5sp4spa3u7RLyetrekE4oS" --sudo-l "jmrTC9JXgadTFmlvNe6Xs20b6dt3ANS9" -m suid
  ```
  <samp>After execution, escalate with:</samp>
  ```bash
  /bin/bash -p
  ```

</details>

<br>

## <samp>▌ <u>0x05_EXECUTION_&_EVIDENCES</u></samp>

<details>
  <summary><code>Click to expand Proof of Concept Gallery...</code></summary>

  ### <samp>1. The Interface (UX/UI)</samp>
  <samp>Advanced argument parsing with custom banners, visual feedback, and a clean help menu inspired by the Fsociety aesthetic.</samp>
  <p align="center">
    <img src="https://github.com/user-attachments/assets/7d45b502-bb3d-46db-bea8-a658cda1a284" alt="Fsociety Help Menu" width="100%"/>
  </p>

  ### <samp>2. Exploit Execution (Nuclear Mode)</samp>
  <samp>The tool automates the "Jailbuilder" phase (resolving dependencies) and the "Nuclear Configuration" phase (stripping namespaces/capabilities) before delivering the payload.</samp>
  <p align="center">
    <img src="https://github.com/user-attachments/assets/8f556929-88ec-4732-a44e-369a5f3e6358" alt="Exploit Execution" width="100%"/>
  </p>

  ### <samp>3. Root Access Confirmed (Shadow PWNED)</samp>
  <samp>Verification of the `shadow` overwrite attack. Successful authentication as <code>root</code> using the injected password.</samp>
  <p align="center">
    <img src="https://github.com/user-attachments/assets/b71cd190-d25a-428b-af94-0320dcae896d" alt="Root Access" width="100%"/>
  <samp>Evidence #2</samp>
    <img src="https://github.com/user-attachments/assets/0cf6d381-225f-4201-a97a-c28ce474b7d1" alt="Root Access" width="100%"/>
  </p>

  ### <samp>4. SUID Persistence</samp>
  <samp>Verification of the sticky bit set on <code>/bin/bash</code>, creating a permanent backdoor for local privilege escalation.</samp>
  <p align="center">
    <img src="https://github.com/user-attachments/assets/69d4605c-2140-4df5-9779-fe59c6f25505" alt="SUID Persistence" width="100%"/>
  <samp>Evidence #2</samp>
    <img src="https://github.com/user-attachments/assets/442d1c14-a77f-4de4-a11a-9541e8ac6a6c" alt="Root Access" width="100%"/>
  </p>
  </p>

</details>

<br>

<br>

## <samp>▌ <u>0x06_MENU_&_OPTIONS</u></samp>

<details>
  <summary><code>Click to view full Command Line Interface...</code></summary>

  <br>

  ### <samp>1. Core Targeting</samp>
  <samp>Essential arguments to define the scope and authentication.</samp>

  | <samp>Argument</samp> | <samp>Description</samp> | <samp>Required</samp> |
  | :--- | :--- | :---: |
  | <samp><code>-t, --target</code></samp> | <samp>Path to the vulnerable wrapper binary (e.g., <code>/opt/debug</code>).</samp> | <b><font color="#ff4500">YES</font></b> |
  | <samp><code>-P, --wrapper-pass</code></samp> | <samp>Administrative password required by the custom wrapper.</samp> | <samp>NO</samp> |
  | <samp><code>-sudo, --sudo-l</code></samp> | <samp>Current user's password (if <code>sudo</code> is needed to run the wrapper).</samp> | <samp>NO</samp> |

  <br>

  ### <samp>2. Payload Modes</samp>
  <samp>Select the attack vector and configure specific parameters.</samp>

  | <samp>Argument</samp> | <samp>Description</samp> | <samp>Context</samp> |
  | :--- | :--- | :--- |
  | <samp><code>-m, --mode</code></samp> | <samp>Attack mode: <code>shadow</code>, <code>suid</code>, <code>rce</code>, <code>read</code>.</samp> | <b><font color="#ff4500">YES</font></b> |
  | <samp><code>--root-pass</code></samp> | <samp>New password for root (Default: <code>fsociety-pw3ned!</code>).</samp> | <samp>Mode: <code>shadow</code></samp> |
  | <samp><code>-c, --command-exec</code></samp> | <samp>Command to execute on the host (Dynamic binary import).</samp> | <samp>Mode: <code>rce</code></samp> |
  | <samp><code>--read-file</code></samp> | <samp>Absolute path of the file to exfiltrate from the host.</samp> | <samp>Mode: <code>read</code></samp> |

  <br>

  ### <samp>3. OpSec & Miscellaneous</samp>
  <samp>Operational security and verbosity controls.</samp>

  | <samp>Argument</samp> | <samp>Description</samp> | <samp>Default</samp> |
  | :--- | :--- | :--- |
  | <samp><code>-w, --workspace</code></samp> | <samp>Temporary directory for <code>rootfs</code> creation.</samp> | <samp><code>/tmp/fsociety_ghost</code></samp> |
  | <samp><code>-v, --verbose</code></samp> | <samp>Enable "Matrix Mode" (Deep debugging logs & JSON dump).</samp> | <samp>False</samp> |
  | <samp><code>--cleanup</code></samp> | <samp>Wipe the workspace and artifacts after execution.</samp> | <samp>False</samp> |

</details>

<br>

---

<p align="center">
  <samp><strong><font color="#ff4500">WE ARE FSOCIETY. WE ARE FINALLY FREE. WE ARE FINALLY AWAKE.</font></strong></samp>
</p>
