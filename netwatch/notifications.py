"""Optional local desktop notifications. No messages leave this machine."""
import json
import platform
import shutil
import subprocess
import base64
import html
from datetime import datetime


def desktop(title, body):
    system = platform.system()
    try:
        if system == "Darwin":
            command = ["osascript", "-e", f"display notification {json.dumps(body, ensure_ascii=False)} with title {json.dumps(title, ensure_ascii=False)}"]
        elif system == "Linux" and shutil.which("notify-send"):
            command = ["notify-send", "--app-name=NetWatch", title, body]
        elif system == "Windows":
            xml = '<toast><visual><binding template="ToastGeneric"><text>' + html.escape(title) + '</text><text>' + html.escape(body) + '</text></binding></visual></toast>'
            content = base64.b64encode(xml.encode()).decode()
            script = "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] > $null; "
            script += "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] > $null; "
            script += "$xml=New-Object Windows.Data.Xml.Dom.XmlDocument; $xml.LoadXml([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + content + "'))); "
            script += "$toast=[Windows.UI.Notifications.ToastNotification]::new($xml); [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Microsoft.Windows.PowerShell').Show($toast)"
            command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.b64encode(script.encode("utf-16le")).decode()]
        else:
            return {"sent": False, "reason": "Уведомления доступны через macOS Notification Center / Linux notify-send; Windows toast требует зарегистрированного приложения"}
        result = subprocess.run(command, capture_output=True, timeout=3)
        return {"sent": result.returncode == 0, "reason": result.stderr.decode("utf-8", "replace")[:300] or None}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"sent": False, "reason": str(exc)}


class AlertPolicy:
    def __init__(self):
        self.failed = self.recovered = 0
        self.notified = False

    def update(self, snapshot, settings):
        if settings.maintenance_until and datetime.fromisoformat(snapshot.timestamp) < datetime.fromisoformat(settings.maintenance_until):
            self.failed = self.recovered = 0
            return None
        if snapshot.cause.status != "ok":
            self.failed += 1
            self.recovered = 0
            if self.failed >= settings.notify_after and not self.notified:
                self.notified = True
                return "NetWatch: проблема со связью", snapshot.cause.summary
        else:
            self.recovered += 1
            self.failed = 0
            if self.notified and self.recovered >= settings.recover_after:
                self.notified = False
                return "NetWatch: связь восстановлена", "Контрольные проверки снова проходят."
        return None
