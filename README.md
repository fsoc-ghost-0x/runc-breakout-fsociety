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

---

<p align="center">
  <samp><strong><font color="#ff4500">WE ARE FSOCIETY. WE ARE FINALLY FREE. WE ARE FINALLY AWAKE.</font></strong></samp>
</p>
```
