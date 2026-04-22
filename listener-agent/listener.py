import os
import time
import socket
import random
from datetime import datetime, timezone

import requests
import xml.etree.ElementTree as ET

try:
    import win32evtlog  # type: ignore
except ImportError:
    win32evtlog = None

API_URL = os.getenv("API_URL", "http://localhost:4000/logs/ingest")
API_KEY = os.getenv("INGEST_API_KEY", "dev-ingest-key-very-strong")
HOSTNAME = socket.gethostname()
MODE = os.getenv("LISTENER_MODE", "windows").lower()
CHANNELS = [c.strip() for c in os.getenv("WINDOWS_CHANNELS", "Security,System").split(",") if c.strip()]
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "5"))

SAMPLE_EVENTS = [
    ("4625", "warning", "windows-security", "Failed login attempt detected"),
    ("1", "info", "sysmon", "Process started: notepad.exe"),
    ("3", "high", "edr", "Possible brute force from 10.0.0.5"),
    ("9999", "critical", "edr", "PowerShell -Enc suspicious payload"),
]


def map_level(level):
    if level in (1, 2):
        return "critical"
    if level == 3:
        return "high"
    if level == 4:
        return "warning"
    return "info"


def post_payload(payload):
    r = requests.post(API_URL, json=payload, headers={"x-api-key": API_KEY}, timeout=10)
    print(f"[{payload['timestamp']}] status={r.status_code} source={payload['source']} event={payload['event_id']} msg={payload['message'][:100]}")


def send_simulated_log():
    event_id, severity, source, message = random.choice(SAMPLE_EVENTS)
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": HOSTNAME,
        "event_id": event_id,
        "severity": severity,
        "source": source,
        "message": message,
        "raw": f"raw event {event_id} :: {message}",
    }
    post_payload(payload)


def iter_windows_events():
    if win32evtlog is None:
        raise RuntimeError("pywin32 non installe. Lance: pip install pywin32")
    query = "*[System[(Level=1 or Level=2 or Level=3 or Level=4)]]"
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
    for channel in CHANNELS:
        handle = win32evtlog.EvtQuery(channel, flags, query)
        while True:
            events = win32evtlog.EvtNext(handle, 20, 0)
            if not events:
                break
            for event in events:
                xml_data = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                root = ET.fromstring(xml_data)
                system = root.find("./System")
                if system is None:
                    continue
                event_id = system.findtext("./EventID", default="unknown")
                provider_node = system.find("./Provider")
                provider = provider_node.attrib.get("Name", "windows") if provider_node is not None else "windows"
                level = int(system.findtext("./Level", default="0"))
                message = (root.findtext("./RenderingInfo/Message", default="") or "").strip()
                if not message:
                    message = f"EventID {event_id} sur {channel}"
                time_created = system.find("./TimeCreated")
                ts = datetime.now(timezone.utc).isoformat()
                if time_created is not None and "SystemTime" in time_created.attrib:
                    ts = time_created.attrib["SystemTime"]
                yield {
                    "timestamp": ts,
                    "host": HOSTNAME,
                    "event_id": str(event_id),
                    "severity": map_level(level),
                    "source": f"{channel}:{provider}",
                    "message": message.replace("\n", " ").strip(),
                    "raw": xml_data[:6000],
                }


if __name__ == "__main__":
    print(f"Listener SOCket demarre... mode={MODE}")
    while True:
        try:
            if MODE == "simulated":
                send_simulated_log()
            else:
                sent_any = False
                for payload in iter_windows_events():
                    post_payload(payload)
                    sent_any = True
                if not sent_any:
                    print("Aucun nouvel evenement Windows detecte.")
        except Exception as exc:
            print(f"Erreur listener: {exc}")
        time.sleep(POLL_SECONDS)
