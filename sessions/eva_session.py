#!/usr/bin/env python3
# made by:    _    ____   ____    _    _   _  ____ _____ _     ___
#▄████▄ █████▄  ▄█████ ▄████▄ ███  ██  ▄████  ██████ ██     ▄████▄
#██▄▄██ ██▄▄██▄ ██     ██▄▄██ ██ ▀▄██ ██  ▄▄▄ ██▄▄   ██     ██  ██
#██  ██ ██   ██ ▀█████ ██  ██ ██   ██  ▀███▀  ██▄▄▄▄ ██████ ▀████▀
# --------------------------------------------------------------------- 

import json
import getpass
import os
import signal
import subprocess
from datetime import datetime, timezone

from colorama import Fore,Back,Style

from config import API_ENDPOINT, MAPS_DIR, REPORTS_DIR, SESSIONS_DIR, username
from modules.attack_map import generate_attack_map_files, open_attack_map
from modules.llm import LLM
from modules.reporting import build_html_report, open_report_file, try_generate_pdf
from modules.tooling import (
    count_sudo_invocations,
    enforce_sudo_for_scanners,
    extract_tools,
    find_missing_local_paths,
    install_one_liner,
    normalize_sudo_invocations,
    patch_missing_wordlists,
    strip_output_flags,
    tool_exists,
)
from modules.workflow import build_workflow_context
from utils.system import (
    checkAnthropicKey,
    checkAPI,
    checkGeminiKey,
    checkOpenAIKey,
    get_current_version,
    graceful_exit,
)
from utils.ui import cyber, menu, raw_input, spinner_start, spinner_stop


# +-------------------------------------------+
# | Main core  -██                            |
# | Handler for Eva utilities and             |
# | Initialization and session manag          |
# +-------------------------------------------+


class Eva:
    def __init__(self, session_path, backend, go_menu):
        self.session_path = session_path
        self.last_output = ""
        self.backend = backend
        self.sessionName = self.session_path.stem
        self.memory = {
            "backend": backend,
            "timeline": [],
            "attack_map_html": "",
            "attack_map_json": "",
        }
        self.go_menu = go_menu
        self.app_version = get_current_version()
        if session_path.exists():
            self.memory = json.loads(session_path.read_text())
            self.backend = self.memory.get("backend", backend)

        self.model = LLM(self.backend)
        self._hydrate_model_context()

    def _hydrate_model_context(self):
        history = []
        restored_last_output = ""
        for item in self.memory.get("timeline", []):
            item_type = item.get("type")
            if item_type == "user":
                content = str(item.get("content", "")).strip()
                if content:
                    history.append({"role": "user", "content": content})
            elif item_type == "analysis":
                content = str(item.get("content", "")).strip()
                if content:
                    history.append({"role": "assistant", "content": content})
            elif item_type == "command":
                output = item.get("output", "")
                if isinstance(output, str):
                    restored_last_output = output

        self.model.history = history
        self.last_output = restored_last_output

    def save(self):
        self.session_path.write_text(json.dumps(self.memory, indent=2))

    def change_model_menu(self):
        """
        Model menu during session
        """
        options = [
            f"Use WhiteRabbit-Neo LLM locally {'::[SELECTED]' if self.backend=='ollama' else ''}",
            f"Use OpenAI GPT-5 {'::[SELECTED]' if self.backend=='gpt' else ''}",
            f"Use G4F.dev {'::[SELECTED]' if self.backend=='g4f' else ''}",
            f"Use Anthropic Claude {'::[SELECTED]' if self.backend=='anthropic' else ''}",
            f"Use Google Gemini {'::[SELECTED]' if self.backend=='gemini' else ''}",

            f"Use Custom API endpoint [{API_ENDPOINT}] {'::[SELECTED]' if self.backend=='api' else ''}"
        ]
        sel = menu("CHANGE BACKEND", options)
        if sel == 0:
            self.backend = "ollama"
            self.memory["backend"] = self.backend
            self.save()
        elif sel == 1:
            self.backend = "gpt"
            checkOpenAIKey()
            self.memory["backend"] = self.backend
            self.save()
        elif sel == 2:
            self.backend = "g4f"
            self.memory["backend"] = self.backend
            self.save()
        elif sel == 3:
            self.backend = "anthropic"
            checkAnthropicKey()
            self.memory["backend"] = self.backend
            self.save()
        elif sel == 4:
            self.backend = "gemini"
            checkGeminiKey()
            self.memory["backend"] = self.backend
            self.save()
        elif sel == 5:
            self.backend = "api"
            checkAPI()
            self.memory["backend"] = self.backend
            self.save()
        self.model = LLM(self.backend)
        self._hydrate_model_context()

    def rename_session(self):
        cyber("Type in the desired name for this session")
        new_name = raw_input("⯁⮞ ").strip()
        if not new_name:
            cyber("[!] Session name cannot be empty.", color=Fore.RED)
            return
        if new_name == self.sessionName:
            cyber("[!] New name is the same as current name.", color=Fore.YELLOW)
            return
        #
        invalid_chars = '<>:"/\\|?*'
        if any(char in new_name for char in invalid_chars):
            cyber("[!] Invalid characters in name. Avoid < > : \" / \\ | ? *", color=Fore.RED)
            return
        new_path = SESSIONS_DIR / f"{new_name}.json"
        if new_path.exists():
            cyber("[!] A session with that name already exists.", color=Fore.YELLOW)
            return
        # Rename the session file
        self.session_path.rename(new_path)
        self.session_path = new_path
        self.sessionName = new_name
        self.save()
        cyber(f"Session renamed to {new_name}", color=Fore.GREEN)

    def run_command(self, cmd):
        original_cmd = cmd
        cmd = strip_output_flags(cmd)
        if cmd != original_cmd:
            cyber("[i] Removed file output flags to keep live logs in session context", color=Fore.YELLOW)

        cmd, wordlist_notes = patch_missing_wordlists(cmd)
        for note in wordlist_notes:
            cyber(f"[i] {note}", color=Fore.YELLOW)

        cmd, forced_sudo = enforce_sudo_for_scanners(cmd)
        if forced_sudo:
            cyber("[i] Added sudo for privileged network scanner command", color=Fore.YELLOW)

        missing_tools = [tool for tool in extract_tools(cmd) if not tool_exists(tool)]
        if missing_tools:
            for tool in missing_tools:
                install_cmd = install_one_liner(tool)
                if install_cmd:
                    cyber(f"[!] Required tool not found: {tool}", color=Fore.YELLOW)
                    print(Fore.CYAN + f"Install + run one-liner:\n{install_cmd} && {cmd}\n")
                    choice = raw_input("[I]nstall+Run | [R]un anyway | [S]kip > ").strip().lower()
                    if choice == "i":
                        cmd = f"{install_cmd} && {cmd}"
                    elif choice == "s":
                        print(Fore.YELLOW + "// 🜂 Command skipped")
                        return
                else:
                    cyber(f"[!] Tool not found and no installer hint available: {tool}", color=Fore.YELLOW)
                    choice = raw_input("[R]un anyway | [S]kip > ").strip().lower()
                    if choice == "s":
                        print(Fore.YELLOW + "// 🜂 Command skipped")
                        return

        missing_paths = find_missing_local_paths(cmd)
        if missing_paths:
            cyber("[!] Missing local files/directories detected", color=Fore.YELLOW)
            for path in missing_paths:
                print(Fore.YELLOW + f" - {path}")
            choice = raw_input("[S]kip (Recommended) | [R]un anyway > ").strip().lower()
            if choice != "r":
                print(Fore.YELLOW + "// 🜂 Command skipped")
                return

        run_cmd = normalize_sudo_invocations(cmd)
        sudo_calls = count_sudo_invocations(run_cmd)
        sudo_password = None
        if sudo_calls > 0:
            try:
                sudo_password = getpass.getpass("Input sudo password: ")
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n// 🜂 Sudo prompt cancelled")
                return
            if not sudo_password:
                print(Fore.YELLOW + "// 🜂 Empty password, command skipped")
                return

        cyber(f"EXECUTING → {cmd}")

        proc = subprocess.Popen(
            run_cmd, shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid
        )
        out = ""
        return_code = None
        try:
            if sudo_password and proc.stdin:
                proc.stdin.write((sudo_password + "\n") * max(2, sudo_calls + 1))
                proc.stdin.flush()
                proc.stdin.close()
            for line in proc.stdout:
                print(line, end="")
                out += line
            return_code = proc.wait()
        except KeyboardInterrupt:
            os.killpg(os.getpgid(proc.pid), signal.SIGINT)
            print(Fore.RED + "\n/// 🜂 Command stopped by user.")
            return_code = proc.wait()
        if not out.strip():
            notice = f"[EVA_NOTICE] Command produced no stdout/stderr. exit_code={return_code if return_code is not None else 'unknown'}"
            out = notice + "\n"
            print(Fore.YELLOW + notice)
        self.last_output = out
        self.memory["timeline"].append({
            "type": "command",
            "cmd": cmd,
            "output": out
        })
        self.save()

    def generate_report(self):
        if not self.memory.get("timeline"):
            cyber("[!] No session data available to report.", color=Fore.YELLOW)
            return

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base = f"{self.sessionName}_{ts}"
        html_path = REPORTS_DIR / f"{base}.html"
        pdf_path = REPORTS_DIR / f"{base}.pdf"

        html_content = build_html_report(
            self.sessionName,
            self.backend,
            self.memory["timeline"],
            version=self.app_version,
        )
        html_path.write_text(html_content, encoding="utf-8")

        pdf_ok = try_generate_pdf(html_path, pdf_path)
        html_opened = open_report_file(html_path)
        pdf_opened = open_report_file(pdf_path) if pdf_ok else False

        if pdf_ok:
            cyber(f"[ ✔ ] Report generated.", color=Fore.GREEN)
            print(f"{Style.BRIGHT}{Fore.GREEN}{html_path}\n{pdf_path}\n")
            if html_opened or pdf_opened:
                cyber("[ ✔ ] Opened report in browser", color=Fore.GREEN)
                print(f"{Fore.GREEN}{html_path}")
                if pdf_opened:
                    print(f"{Fore.GREEN}{pdf_path}")
                print()
            else:
                cyber("[!] Could not open browser automatically. Check report path in ~/.config/eva/reports", color=Fore.YELLOW)

        else:
            cyber(
                f"[ ✔ ] HTML report generated.",
                color=Fore.GREEN,
            )
            print(f"{Style.BRIGHT}{Fore.GREEN}{html_path}\n {Fore.RED} :: PDF was not created (wkhtmltopdf not found!) \n")
            if html_opened:
                cyber("[ ✔ ] Opened report in browser", color=Fore.GREEN)
                print(f"{Fore.GREEN}{html_path}\n")
            else:
                cyber("[!] Could not open browser automatically. Check report path in ~/.config/eva/reports", color=Fore.YELLOW)

    def generate_attack_map(self):
        if not self.memory.get("timeline"):
            cyber("[!] No session data available to map.", color=Fore.YELLOW)
            return None

        html_path, json_path, graph = generate_attack_map_files(
            self.sessionName,
            self.memory["timeline"],
            MAPS_DIR,
            version=self.app_version,
        )
        self.memory["attack_map_html"] = str(html_path)
        self.memory["attack_map_json"] = str(json_path)
        self.save()
        cyber(
            f"[ ✔ ] Attack map generated.",
            color=Fore.GREEN,
        )
        print(f"{Style.BRIGHT}{Fore.BLUE}{html_path} (nodes={graph['meta']['node_count']}, edges={graph['meta']['edge_count']}) \n")
        return html_path

    def view_attack_map(self):
        map_path = self.memory.get("attack_map_html", "").strip()
        if not map_path:
            generated = self.generate_attack_map()
            if not generated:
                return
            map_path = str(generated)

        opened = open_attack_map(map_path)
        if opened:
            cyber(f"[ ✔ ] Opened session map in browser", color=Fore.GREEN)
            print(f"{Fore.GREEN} {map_path} \n")
        else:
            cyber("[!] Could not open browser automatically. Check map path in ~/.config/eva/attack_maps", color=Fore.YELLOW)

    def _render_session_header(self):
        os.system("clear")
        cyber(":: 🍎 EVA ONLINE :: ")
        print(Fore.GREEN + "⯁⮞ ˹E˼xploit ˹V˼ector ˹A˼gent \n⬢  Current Model: " + Fore.CYAN + self.backend + f"\n{Fore.GREEN}𖨠 Session Name: " + Fore.YELLOW + self.sessionName)
        print(Fore.CYAN + "/// type /exit to quit the program anytime")
        print(Fore.CYAN + "/// type /model to change current model")
        print(Fore.CYAN + "/// type /rename to change a session name")
        print(Fore.CYAN + "/// type /viewmap to open attack map with last findings.")
        print(Fore.CYAN + "/// type /report to generate a report in PDF and HTML.")
        print(Fore.CYAN + "/// type /menu to go back to sessions menu\n\n")

    def _render_timeline(self):
        for item in self.memory["timeline"]:
            if item["type"] == "user":
                print(Fore.GREEN + f"{username.upper()} > {item['content']}\n")

            elif item["type"] == "analysis":
                cyber("ANALYSIS", color=Style.BRIGHT + Fore.CYAN)
                print(Style.BRIGHT + Fore.CYAN + item["content"] + Style.RESET_ALL + "\n")

            elif item["type"] == "command":
                cyber(f"EXECUTED → {item['cmd']}", color=Fore.CYAN)
                print(item["output"] + "\n")

    def chat(self):
        self._render_session_header()
        self._render_timeline()

        while True:
            try:
                user = raw_input(Fore.GREEN + f"\n{username.upper()} > ")
            except KeyboardInterrupt:
                print()
                continue
            if user.lower() in ("exit", "quit", "/exit","/quit","q"):
                self.save()
                graceful_exit()
            if user.lower() in ("menu", "/menu"):
                return self.go_menu()
            if user.lower() in ("rename", "/rename"):
                self.rename_session()
                self._render_session_header()
                self._render_timeline()
                continue
            
            if user.lower() in ("help", "/help"):
                print(Fore.CYAN + "/// type /exit to quit the program anytime")
                print(Fore.CYAN + "/// type /model to change current model")
                print(Fore.CYAN + "/// type /rename to change a session name")
                print(Fore.CYAN + "/// type /viewmap to open attack map with last findings.")
                print(Fore.CYAN + "/// type /report to generate a report in PDF and HTML.")
                print(Fore.CYAN + "/// type /menu to go back to sessions menu\n\n")
                print(Style.BRIGHT + Fore.YELLOW + "->  Ask any question to EVA to request assistance, if no commands are generated to run, ask EVA explicitly for command generation.")
                continue

            if user.lower() in ("model", "/model"):
                self.change_model_menu()
                self._render_session_header()
                self._render_timeline()
                continue
            if user.lower() in ("viewmap", "/viewmap","map","/map"):
                self.view_attack_map()
                continue
            if user.lower() in ("report", "/report"):
                self.generate_report()
                continue

            spinner_start()
            spinner_stopped = False
            analysis_header_shown = False
            on_stream_start = None
            if self.backend == "ollama":
                def _on_stream_start():
                    nonlocal spinner_stopped, analysis_header_shown
                    if not spinner_stopped:
                        spinner_stop()
                        spinner_stopped = True
                    if not analysis_header_shown:
                        cyber("ANALYSIS", color=Style.BRIGHT + Fore.CYAN)
                        analysis_header_shown = True

                on_stream_start = _on_stream_start

            try:
                workflow_context = build_workflow_context(self.memory.get("timeline", []), self.last_output)
                resp = self.model.query(
                    user,
                    self.last_output,
                    on_stream_start=on_stream_start,
                    workflow_context=workflow_context,
                )
            except KeyboardInterrupt:
                if not spinner_stopped:
                    spinner_stop()
                print(Fore.YELLOW + "\n// 🜂 Request cancelled")
                continue

            if not spinner_stopped:
                spinner_stop()
                spinner_stopped = True
            self.memory["timeline"].append({
                "type": "user",
                "content": user
            })
            self.memory["timeline"].append({
                "type": "analysis",
                "content": resp["analysis"]
            })
            self.save()
            if not analysis_header_shown:
                cyber("ANALYSIS", color=Style.BRIGHT + Fore.CYAN)
                analysis_header_shown = True
            if not resp.get("__streamed"):
                print(Style.BRIGHT + Fore.CYAN + resp["analysis"] + Style.RESET_ALL)
            break_outer = False
            for cmd in resp["commands"]:

                while True:
                    try:
                        print("\n\n")
                        print(f" {Style.BRIGHT}{Back.RED}{Fore.CYAN}$ {cmd}{Style.RESET_ALL} \n")
                        print(f"{Style.BRIGHT}{Fore.CYAN} [| [R]un | [S]kip | [A]sk | [G]enerate HTML Report | [V]iew attack map | [Q]uit |]\n")
                        choice = raw_input("> ").strip().lower()
                    except KeyboardInterrupt:
                        print()
                        break_outer = True
                        break

                    if choice == "r":
                        self.run_command(cmd)
                        spinner_start()
                        spinner_stopped = False
                        analysis_header_shown = False
                        on_stream_start = None
                        if self.backend == "ollama":
                            def _on_stream_start():
                                nonlocal spinner_stopped, analysis_header_shown
                                if not spinner_stopped:
                                    spinner_stop()
                                    spinner_stopped = True
                                if not analysis_header_shown:
                                    cyber("ANALYSIS", color=Style.BRIGHT + Fore.CYAN)
                                    analysis_header_shown = True

                            on_stream_start = _on_stream_start

                        try:
                            workflow_context = build_workflow_context(self.memory.get("timeline", []), self.last_output)
                            resp = self.model.query(
                                "Analyze the previous command output and continue.",
                                self.last_output,
                                on_stream_start=on_stream_start,
                                workflow_context=workflow_context,
                            )
                        except KeyboardInterrupt:
                            if not spinner_stopped:
                                spinner_stop()
                            print(Fore.YELLOW + "\n// 🜂 Request cancelled")
                            break

                        if not spinner_stopped:
                            spinner_stop()
                            spinner_stopped = True
                        self.memory["timeline"].append({
                            "type": "analysis",
                            "content": resp["analysis"]
                        })
                        self.save()
                        if not analysis_header_shown:
                            cyber("ANALYSIS", color=Style.BRIGHT + Fore.CYAN)
                            analysis_header_shown = True
                        if not resp.get("__streamed"):
                            print(Style.BRIGHT + Fore.CYAN + resp["analysis"] + Style.RESET_ALL)
                        break

                    elif choice == "a":
                        break_outer = True
                        break

                    elif choice == "s":
                        break

                    elif choice == "q":
                        self.save()
                        graceful_exit()
                    elif choice == "g":
                        self.generate_report()
                    elif choice == "v":
                        self.view_attack_map()

                    else:
                        print("// 🜂 Not a valid input, please type R, S, A, G, V or Q.")
                if break_outer:
                    break
            self.save()
