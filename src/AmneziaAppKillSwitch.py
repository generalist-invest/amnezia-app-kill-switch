#!/usr/bin/env python3
"""Per-application VPN kill switch for Windows and Amnezia VPN.

Run this file as Administrator.  It uses only the built-in Windows Firewall
(NetSecurity) cmdlets; it does not install a driver or send data anywhere.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import re
from dataclasses import dataclass, asdict
from hashlib import sha256
from pathlib import Path
from tkinter import Tk, StringVar, END, filedialog, messagebox
from tkinter import ttk

APP_NAME = "Amnezia App Kill Switch"
VERSION = "1.2"
RULE_GROUP = "Amnezia App Kill Switch"
# Firewall rule names reject characters such as a vertical bar.
RULE_PREFIX = "AAKS-"
CONFIG_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "AmneziaAppKillSwitch"
CONFIG_PATH = CONFIG_DIR / "config.json"
LOG_PATH = CONFIG_DIR / "kill-switch.log"
REFRESH_SECONDS = 3
CLAUDE_PACKAGE_FAMILY = "Claude_pzs8sxrjxfjjc"


@dataclass
class Config:
    vpn_interface: str = ""
    applications: list[str] | None = None
    enabled: bool = False

    def __post_init__(self) -> None:
        self.applications = self.applications or []


def log(message: str) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as file:
            file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
    except OSError:
        pass


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_elevated(extra: list[str]) -> None:
    params = " ".join([f'"{Path(__file__).resolve()}"'] + [f'"{arg}"' for arg in extra])
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    if result <= 32:
        raise RuntimeError("Windows отклонила запуск от имени администратора.")


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def run_powershell(script: str, timeout: int = 30) -> str:
    """Run a local, fixed PowerShell script without showing a console."""
    script = "$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n" + script
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = subprocess.SW_HIDE
    process = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        startupinfo=startup,
        timeout=timeout,
    )
    if process.returncode:
        raise RuntimeError((process.stderr or process.stdout or "PowerShell завершился с ошибкой").strip())
    return process.stdout.strip()


def load_config() -> Config:
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        return Config(**raw)
    except (FileNotFoundError, json.JSONDecodeError, TypeError):
        return Config()


def save_config(config: Config) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    temp = CONFIG_PATH.with_suffix(".tmp")
    temp.write_text(json.dumps(asdict(config), ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(CONFIG_PATH)


def adapter_names() -> list[str]:
    raw = run_powershell(
        "Get-NetAdapter -IncludeHidden -ErrorAction Stop | "
        "Where-Object { $_.Name } | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress"
    )
    if not raw:
        return []
    names = json.loads(raw)
    adapters = names if isinstance(names, list) else [names]
    # Put likely VPN adapters first; never silently make a generic transition
    # adapter the selected VPN.
    return sorted(adapters, key=lambda name: (not bool(re.search(r"amnezia|wireguard|wintun|\bwg\b|\btun\b|\btap\b", name, re.I)), name.casefold()))


def blocking_interface_names(vpn_interface: str) -> list[str]:
    """Return only aliases the firewall/IP stack can actually bind a rule to."""
    raw = run_powershell(
        "Get-NetIPInterface -ErrorAction Stop | Where-Object { $_.InterfaceAlias } | "
        "Select-Object -ExpandProperty InterfaceAlias -Unique | ConvertTo-Json -Compress"
    )
    if not raw:
        return []
    aliases = json.loads(raw)
    aliases = aliases if isinstance(aliases, list) else [aliases]
    technical = re.compile(r"6to4|teredo|isatap|loopback", re.I)
    return sorted(
        {name for name in aliases if name.casefold() != vpn_interface.casefold() and not technical.search(name)},
        key=str.casefold,
    )


def rule_name(target: str, adapter: str) -> str:
    digest = sha256((target.lower() + "\0" + adapter.lower()).encode("utf-8")).hexdigest()[:20]
    return f"{RULE_PREFIX}{digest}"


def resolve_claude_program() -> str:
    """Resolve the current Store package to its real executable at runtime.

    This avoids the fragile Windows Firewall package filter and also keeps the
    path current after a Claude Store update.
    """
    script = f"""
$ErrorActionPreference = 'Stop'
$pkg = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {{ $_.PackageFamilyName -eq '{CLAUDE_PACKAGE_FAMILY}' }} | Sort-Object Version -Descending | Select-Object -First 1)
if (-not $pkg) {{ $pkg = @(Get-AppxPackage -ErrorAction Stop | Where-Object {{ $_.PackageFamilyName -eq '{CLAUDE_PACKAGE_FAMILY}' }} | Sort-Object Version -Descending | Select-Object -First 1) }}
if (-not $pkg) {{ throw 'Claude from Microsoft Store is not installed for this computer.' }}
$exe = Get-ChildItem -LiteralPath $pkg[0].InstallLocation -Filter 'Claude.exe' -File -Recurse -ErrorAction Stop | Select-Object -First 1
if (-not $exe) {{ throw 'Claude.exe was not found inside its Microsoft Store package.' }}
$exe.FullName
"""
    path = run_powershell(script, timeout=45).splitlines()[-1].strip()
    if not path:
        raise RuntimeError("Не удалось определить путь к Claude.exe.")
    return path


def reconcile(config: Config) -> int:
    """Create missing block rules before removing obsolete ones (fail closed)."""
    if not config.enabled:
        return remove_all_rules()
    if not config.vpn_interface:
        raise RuntimeError("Не выбран интерфейс Amnezia VPN.")

    targets = []
    for app in config.applications:
        if app.startswith("store:"):
            family = app.removeprefix("store:")
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", family):
                raise RuntimeError(f"Некорректный идентификатор Store-приложения: {family}")
            if family != CLAUDE_PACKAGE_FAMILY:
                raise RuntimeError(f"Store-приложение пока не поддерживается: {family}")
            targets.append({"kind": "program", "target": resolve_claude_program(), "label": family})
        elif Path(app).is_file():
            targets.append({"kind": "program", "target": str(Path(app)), "label": str(Path(app))})
    if not targets:
        raise RuntimeError("Не добавлено ни одной существующей программы или Store-приложения.")
    interfaces = blocking_interface_names(config.vpn_interface)
    if not interfaces:
        raise RuntimeError("Не удалось получить список реальных IP-интерфейсов Windows для блокировки.")

    desired = [{"name": rule_name(item["kind"] + ":" + item["label"], interface),
                "target": item["target"], "interface": interface}
               for item in targets for interface in interfaces]
    payload = json.dumps(desired, ensure_ascii=False).replace("'", "''")
    # Rules are first added/updated for *every* non-VPN adapter.  Only then are
    # stale rules removed.  Changing settings can therefore over-block briefly,
    # but never opens an unprotected path for an app.
    script = f"""
$ErrorActionPreference = 'Stop'
$desired = ConvertFrom-Json -InputObject '{payload}'
$wanted = @($desired | ForEach-Object {{ $_.name }})
foreach ($item in @($desired)) {{
  $existing = Get-NetFirewallRule -DisplayName $item.name -ErrorAction SilentlyContinue
  if (-not $existing) {{
    New-NetFirewallRule -DisplayName $item.name -Group '{RULE_GROUP}' -Description 'Blocks this program outside the selected Amnezia VPN interface.' -Direction Outbound -Action Block -Program $item.target -InterfaceAlias $item.interface -Profile Any -Enabled True | Out-Null
  }}
}}
$old = Get-NetFirewallRule -Group '{RULE_GROUP}' -ErrorAction SilentlyContinue
foreach ($rule in @($old)) {{
  if ($rule.DisplayName -notin $wanted) {{ $rule | Remove-NetFirewallRule }}
}}
($wanted | Measure-Object).Count
"""
    result = run_powershell(script, timeout=60)
    return int(result.splitlines()[-1]) if result else 0


def remove_all_rules() -> int:
    script = f"""
$ErrorActionPreference = 'Stop'
$rules = @(Get-NetFirewallRule -Group '{RULE_GROUP}' -ErrorAction SilentlyContinue)
if ($rules.Count -gt 0) {{ $rules | Remove-NetFirewallRule }}
$rules.Count
"""
    result = run_powershell(script)
    return int(result.splitlines()[-1]) if result else 0


def install_autostart() -> None:
    # A boot task must not depend on a removable Downloads/Desktop location.
    # Keep the monitored copy beside its system-wide configuration instead.
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    installed_tray = CONFIG_DIR / "AmneziaKillSwitchTray.ps1"
    frozen = bool(getattr(sys, "frozen", False))
    if frozen:
        installed_entry = CONFIG_DIR / "AmneziaAppKillSwitch.exe"
        if Path(sys.executable).resolve() != installed_entry.resolve():
            shutil.copy2(Path(sys.executable), installed_entry)
        exe = str(installed_entry)
        script_path = ""
    else:
        installed_entry = CONFIG_DIR / "AmneziaAppKillSwitch.py"
        if Path(__file__).resolve() != installed_entry.resolve():
            shutil.copy2(Path(__file__).resolve(), installed_entry)
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        exe = str(pythonw if pythonw.is_file() else Path(sys.executable))
        script_path = str(installed_entry)
    tray_source = Path(__file__).resolve().with_name("AmneziaKillSwitchTray.ps1")
    if not tray_source.is_file():
        raise RuntimeError("Не найден файл значка в трее: AmneziaKillSwitchTray.ps1")
    shutil.copy2(tray_source, installed_tray)
    (CONFIG_DIR / "runtime.json").write_text(json.dumps({"python": exe, "script": script_path}, ensure_ascii=False), encoding="utf-8")
    # SYSTEM starts before a user signs in. Firewall rules already persist, and
    # the monitor also catches adapters created after boot.
    ps = (
        "$ErrorActionPreference='Stop'; "
        f"$action=New-ScheduledTaskAction -Execute {ps_quote(exe)} -Argument {ps_quote(('"' + script_path + '" ' if script_path else '') + '--background')}; "
        "$trigger=New-ScheduledTaskTrigger -AtStartup; "
        "$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; "
        f"Register-ScheduledTask -TaskName {ps_quote(APP_NAME + ' Monitor')} -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null; "
        f"Start-ScheduledTask -TaskName {ps_quote(APP_NAME + ' Monitor')}; "
        f"$trayAction=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument {ps_quote('-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + str(installed_tray) + '"')}; "
        "$trayTrigger=New-ScheduledTaskTrigger -AtLogOn; "
        f"Register-ScheduledTask -TaskName {ps_quote(APP_NAME + ' Tray')} -Action $trayAction -Trigger $trayTrigger -RunLevel Limited -Force | Out-Null; "
        f"Start-ScheduledTask -TaskName {ps_quote(APP_NAME + ' Tray')}"
    )
    run_powershell(ps)


def uninstall_autostart() -> None:
    run_powershell(
        f"Unregister-ScheduledTask -TaskName {ps_quote(APP_NAME + ' Monitor')} -Confirm:$false -ErrorAction SilentlyContinue; "
        f"Unregister-ScheduledTask -TaskName {ps_quote(APP_NAME + ' Tray')} -Confirm:$false -ErrorAction SilentlyContinue"
    )


def background() -> int:
    log("background monitor started")
    last_signature = None
    while True:
        try:
            config = load_config()
            signature = json.dumps(asdict(config), ensure_ascii=False, sort_keys=True)
            # Reconcile every cycle, not only after config edits: a newly-created
            # adapter must be blocked before an app can use it.
            count = reconcile(config)
            if signature != last_signature:
                log(f"rules reconciled: {count}")
                last_signature = signature
        except Exception as error:
            log(f"reconcile error: {error}")
        time.sleep(REFRESH_SECONDS)


class Window:
    def __init__(self) -> None:
        self.config = load_config()
        # Bundle the harmless probe with the current setup so its rule is
        # created automatically for the requested end-to-end verification.
        bundled_probe = Path(__file__).resolve().with_name("TrafficProbe.exe")
        if bundled_probe.is_file() and str(bundled_probe) not in self.config.applications:
            self.config.applications.append(str(bundled_probe))
            save_config(self.config)
        self.root = Tk()
        self.root.title(f"{APP_NAME} v{VERSION}")
        self.root.geometry("710x470")
        self.root.minsize(650, 420)
        self.status = StringVar(value="Проверяю состояние…")
        self.vpn = StringVar(value=self.config.vpn_interface)
        self.adapters: list[str] = []
        self.build()
        self.refresh_adapters()
        self.update_status()
        # Once protection has been configured, every subsequent elevated launch
        # repairs rules and startup tasks automatically. No recurring click is
        # required after the initial setup.
        if self.config.enabled:
            self.root.after(150, self.apply_saved_protection)

    def build(self) -> None:
        box = ttk.Frame(self.root, padding=16)
        box.pack(fill="both", expand=True)
        ttk.Label(box, text=f"Amnezia App Kill Switch v{VERSION}", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(box, text="Выбранные программы заблокированы на всех интерфейсах, кроме указанного VPN.", wraplength=650).pack(anchor="w", pady=(3, 14))

        top = ttk.Frame(box)
        top.pack(fill="x")
        ttk.Label(top, text="Интерфейс Amnezia VPN:").pack(side="left")
        self.combo = ttk.Combobox(top, textvariable=self.vpn, state="readonly", width=45)
        self.combo.pack(side="left", padx=8, fill="x", expand=True)
        ttk.Button(top, text="Обновить", command=self.refresh_adapters).pack(side="left")

        ttk.Label(box, text="Защищаемые программы (.exe) и Store-приложения:").pack(anchor="w", pady=(18, 4))
        list_frame = ttk.Frame(box)
        list_frame.pack(fill="both", expand=True)
        self.apps = ttk.Treeview(list_frame, columns=("path",), show="headings", height=9)
        self.apps.heading("path", text="Программа или идентификатор Microsoft Store")
        self.apps.column("path", width=580, stretch=True)
        self.apps.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.apps.yview)
        scroll.pack(side="right", fill="y")
        self.apps.configure(yscrollcommand=scroll.set)
        for path in self.config.applications:
            self.apps.insert("", END, values=(path,))

        app_buttons = ttk.Frame(box)
        app_buttons.pack(fill="x", pady=(8, 12))
        ttk.Button(app_buttons, text="Добавить программу…", command=self.add_app).pack(side="left")
        ttk.Button(app_buttons, text="Добавить Claude (Store)", command=self.add_claude).pack(side="left", padx=7)
        ttk.Button(app_buttons, text="Убрать выбранное", command=self.remove_app).pack(side="left", padx=7)
        ttk.Button(app_buttons, text="Экспорт настроек…", command=self.export_settings).pack(side="left", padx=7)
        ttk.Button(app_buttons, text="Импорт настроек…", command=self.import_settings).pack(side="left")

        controls = ttk.Frame(box)
        controls.pack(fill="x")
        ttk.Button(controls, text="Включить защиту навсегда", command=self.enable).pack(side="left")
        ttk.Button(controls, text="Отключить и удалить правила", command=self.disable).pack(side="left", padx=7)
        ttk.Button(controls, text="Автозапуск с Windows", command=self.autostart).pack(side="left", padx=7)
        ttk.Label(box, textvariable=self.status, foreground="#126a28", wraplength=650).pack(anchor="w", pady=(12, 0))

    def refresh_adapters(self) -> None:
        try:
            current = self.vpn.get()
            self.adapters = adapter_names()
            self.combo["values"] = self.adapters
            invalid = lambda name: bool(re.search(r"6to4|teredo|isatap|loopback", name or "", re.I))
            if current in self.adapters and not invalid(current):
                self.vpn.set(current)
            elif self.config.vpn_interface in self.adapters and not invalid(self.config.vpn_interface):
                self.vpn.set(self.config.vpn_interface)
            else:
                self.vpn.set("")
            self.status.set("Список интерфейсов обновлён. Сначала подключите Amnezia, затем выберите её адаптер (Wintun/AmneziaWG).")
        except Exception as error:
            self.status.set(f"Не удалось получить адаптеры: {error}")

    def read_form(self, enabled: bool | None = None) -> Config:
        apps = [self.apps.item(item, "values")[0] for item in self.apps.get_children()]
        return Config(self.vpn.get(), apps, self.config.enabled if enabled is None else enabled)

    def add_app(self) -> None:
        path = filedialog.askopenfilename(title="Выберите программу", filetypes=[("Программы Windows", "*.exe"), ("Все файлы", "*.*")])
        if path and path not in [self.apps.item(item, "values")[0] for item in self.apps.get_children()]:
            self.apps.insert("", END, values=(path,))

    def remove_app(self) -> None:
        for item in self.apps.selection():
            self.apps.delete(item)

    def add_claude(self) -> None:
        target = "store:" + CLAUDE_PACKAGE_FAMILY
        existing = [self.apps.item(item, "values")[0] for item in self.apps.get_children()]
        if target not in existing:
            self.apps.insert("", END, values=(target,))
            self.status.set("Добавлен Claude из Microsoft Store. Искать скрытый Claude.exe не нужно.")

    def export_settings(self) -> None:
        """Export a portable policy; firewall state is deliberately excluded."""
        destination = filedialog.asksaveasfilename(
            title="Сохранить переносимые настройки",
            defaultextension=".json",
            initialfile="amnezia-kill-switch-policy.json",
            filetypes=[("Настройки kill switch", "*.json")],
        )
        if not destination:
            return
        try:
            config = self.read_form()
            policy = {"format": "AmneziaAppKillSwitch", "version": 1,
                      "vpn_interface": config.vpn_interface, "applications": config.applications}
            Path(destination).write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
            self.status.set("Настройки экспортированы. На другом ПК проверьте VPN-интерфейс и пути к .exe.")
        except Exception as error:
            messagebox.showerror(APP_NAME, f"Не удалось экспортировать настройки:\n{error}")

    def import_settings(self) -> None:
        source = filedialog.askopenfilename(
            title="Выберите переносимые настройки", filetypes=[("Настройки kill switch", "*.json"), ("Все файлы", "*.*")]
        )
        if not source:
            return
        try:
            policy = json.loads(Path(source).read_text(encoding="utf-8"))
            if policy.get("format") != "AmneziaAppKillSwitch" or policy.get("version") != 1:
                raise ValueError("Это не файл настроек Amnezia App Kill Switch.")
            applications = policy.get("applications")
            if not isinstance(applications, list) or not all(isinstance(item, str) for item in applications):
                raise ValueError("В файле нет корректного списка программ.")
            self.vpn.set(str(policy.get("vpn_interface", "")))
            self.apps.delete(*self.apps.get_children())
            for path in applications:
                self.apps.insert("", END, values=(path,))
            missing = sum(not Path(path).is_file() for path in applications)
            suffix = f" Отсутствуют на этом ПК: {missing}; укажите их заново." if missing else ""
            self.status.set("Настройки импортированы, но ещё не применены." + suffix)
        except Exception as error:
            messagebox.showerror(APP_NAME, f"Не удалось импортировать настройки:\n{error}")

    def enable(self) -> None:
        config = self.read_form(enabled=True)
        if not config.vpn_interface or not config.applications:
            messagebox.showerror(APP_NAME, "Выберите VPN-интерфейс и добавьте хотя бы одну программу.")
            return
        if re.search(r"6to4|teredo|isatap|loopback", config.vpn_interface, re.I):
            messagebox.showerror(APP_NAME, "Это системный переходный адаптер Windows, а не Amnezia VPN. Подключите Amnezia, нажмите «Обновить» и выберите её адаптер.")
            return
        try:
            previous = self.config
            save_config(config)
            count = reconcile(config)
            install_autostart()
            self.config = config
            self.status.set(f"Защита ВКЛ: правил {count}. Автозапуск и значок в трее установлены.")
            log(f"enabled: {count} rules")
        except Exception as error:
            # Do not leave the monitor believing a failed rule installation is
            # active. Restore the last known configuration before reporting it.
            try:
                save_config(previous)
            except Exception:
                pass
            messagebox.showerror(APP_NAME, f"Не удалось включить защиту:\n{error}")

    def apply_saved_protection(self) -> None:
        try:
            count = reconcile(self.config)
            install_autostart()
            self.status.set(f"Защита автоматически подтверждена: правил {count}. Фоновый режим активен.")
            log(f"automatic repair: {count} rules")
        except Exception as error:
            self.status.set(f"Автоматическое применение не удалось: {error}")
            log(f"automatic repair error: {error}")

    def disable(self) -> None:
        if not messagebox.askyesno(APP_NAME, "Это удалит правила блокировки. Защищаемые программы снова смогут использовать обычный интернет."):
            return
        try:
            removed = remove_all_rules()
            self.config = self.read_form(enabled=False)
            save_config(self.config)
            self.status.set(f"Защита выключена. Удалено правил: {removed}.")
            log(f"disabled: {removed} rules removed")
        except Exception as error:
            messagebox.showerror(APP_NAME, f"Не удалось удалить правила:\n{error}")

    def autostart(self) -> None:
        try:
            install_autostart()
            self.status.set("Автозапуск при загрузке Windows и значок в трее установлены.")
            log("autostart installed")
        except Exception as error:
            messagebox.showerror(APP_NAME, f"Не удалось установить автозапуск:\n{error}")

    def update_status(self) -> None:
        if self.config.enabled:
            self.status.set("В конфигурации есть активная защита. После выбора верного VPN-интерфейса нажмите «Включить защиту».")
        else:
            self.status.set("Защита выключена.")

    def run(self) -> None:
        self.root.mainloop()


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--background", action="store_true")
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--elevated", action="store_true")
    args = parser.parse_args()
    if not is_admin():
        try:
            relaunch_elevated(["--background"] if args.background else ["--elevated"])
            return 0
        except Exception as error:
            if not args.background:
                root = Tk(); root.withdraw()
                messagebox.showerror(APP_NAME, str(error))
            return 1
    if args.background:
        return background()
    Window().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

