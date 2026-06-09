from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ml_predict_then_llm_explain import analyze_event


# ============================================================
# Paths
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


# ============================================================
# FastAPI App
# ============================================================

app = FastAPI(title="MITRE ATT&CK SOC Dashboard")

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class EventInput(BaseModel):
    EventID: str = ""
    Image: str = ""
    CommandLine: str = ""
    ParentImage: str = ""
    ParentCommandLine: str = ""
    User: str = ""
    Computer: str = ""
    TargetFilename: str = ""
    TargetObject: str = ""
    Details: str = ""
    DestinationIp: str = ""
    DestinationPort: str = ""
    SourceIp: str = ""
    SourcePort: str = ""
    QueryName: str = ""
    CurrentDirectory: str = ""


DEMO_EXAMPLES = [
    {
        "id": "powershell_encoded",
        "name": "Encoded PowerShell Execution",
        "expected": "T1059.001 PowerShell",
        "event": {
            "EventID": "1",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "ParentCommandLine": "cmd.exe /c powershell.exe -enc SQBFAFgA...",
            "User": r"corp\alice",
            "Computer": "win10-01",
            "CurrentDirectory": r"C:\Users\alice\Downloads"
        }
    },
    {
        "id": "disable_service",
        "name": "Disable Windows Service",
        "expected": "T1562.001 Impair Defenses",
        "event": {
            "EventID": "1",
            "Image": r"C:\Windows\System32\sc.exe",
            "CommandLine": r'"C:\Windows\System32\sc.exe" config wmiapservs start= disabled',
            "ParentImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ParentCommandLine": "powershell.exe -ExecutionPolicy Bypass",
            "User": r"NT AUTHORITY\SYSTEM",
            "Computer": "project-saopaulo-host",
            "CurrentDirectory": r"C:\Windows\Temp"
        }
    },
    {
        "id": "reg_run_key",
        "name": "Registry Run Key Persistence",
        "expected": "T1547.001 Registry Run Keys",
        "event": {
            "EventID": "13",
            "Image": r"C:\Windows\System32\reg.exe",
            "CommandLine": r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v updater /t REG_SZ /d C:\Users\alice\AppData\Roaming\updater.exe /f',
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "ParentCommandLine": "cmd.exe /c reg add run key",
            "User": r"corp\alice",
            "Computer": "win10-02",
            "TargetObject": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\updater",
            "Details": r"C:\Users\alice\AppData\Roaming\updater.exe"
        }
    },
    {
        "id": "rundll32_proxy",
        "name": "Rundll32 Proxy Execution",
        "expected": "T1218.011 Rundll32",
        "event": {
            "EventID": "1",
            "Image": r"C:\Windows\System32\rundll32.exe",
            "CommandLine": r"rundll32.exe javascript.dll,StartW suspicious_payload",
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "ParentCommandLine": "cmd.exe /c rundll32.exe javascript.dll,StartW suspicious_payload",
            "User": r"corp\bob",
            "Computer": "win10-03",
            "CurrentDirectory": r"C:\Users\bob\Downloads"
        }
    },
    {
        "id": "vssadmin_delete",
        "name": "Delete Shadow Copies",
        "expected": "T1490 Inhibit System Recovery",
        "event": {
            "EventID": "1",
            "Image": r"C:\Windows\System32\vssadmin.exe",
            "CommandLine": "vssadmin.exe delete shadows /all /quiet",
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "ParentCommandLine": "cmd.exe /c vssadmin.exe delete shadows /all /quiet",
            "User": r"NT AUTHORITY\SYSTEM",
            "Computer": "win10-04",
            "CurrentDirectory": r"C:\Windows\System32"
        }
    },
    {
        "id": "web_shell",
        "name": "Possible Web Shell Activity",
        "expected": "T1505.003 Web Shell",
        "event": {
            "EventID": "11",
            "Image": r"C:\Windows\System32\inetsrv\w3wp.exe",
            "CommandLine": "w3wp.exe -ap DefaultAppPool",
            "ParentImage": r"C:\Windows\System32\services.exe",
            "ParentCommandLine": "services.exe",
            "User": r"IIS APPPOOL\DefaultAppPool",
            "Computer": "web-server-01",
            "TargetFilename": r"C:\inetpub\wwwroot\uploads\shell.aspx"
        }
    }
]


# ============================================================
# Routes
# ============================================================

@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/examples")
def get_examples():
    return DEMO_EXAMPLES


@app.post("/api/analyze")
def analyze_event_api(event: EventInput):
    event_dict = event.model_dump()
    return analyze_event(event_dict)


# ============================================================
# Run directly with: python3 app.py
# ============================================================

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
