# 📚 Local Web Attendance System (Flask + SQLite)

A fully **offline** attendance registration system that runs on your laptop over a local Wi-Fi router. Students connect to the classroom Wi-Fi, scan a QR code, and register — one submission per device/IP every 24 hours.

## 📁 Project structure

```
attendance-system/
├── app.py                  # The complete Flask application
├── attendance.db           # SQLite database (auto-created on first run)
├── .secret_key             # Auto-generated cookie signing key (do not delete mid-day)
└── templates/
    ├── base.html           # Shared layout + design system (dark tech theme)
    ├── index.html          # Registration form (Arabic, RTL, HTML5 validation)
    ├── success.html        # Success screen
    ├── blocked.html        # "Already registered today" screen
    └── admin.html          # Teacher-only attendance list (localhost only)
```

## ⚙️ Setup (one time)

1. Install Python 3.9+ on the laptop.
2. Install dependencies:

```bash
pip install flask itsdangerous
```

> `itsdangerous` ships with Flask, so `pip install flask` alone is usually enough.

No manual database initialization is needed — `attendance.db` and the `students` table are created automatically on first run.

## ▶️ Running the server

Port 80 requires elevated privileges:

**Windows** — open Command Prompt *as Administrator*:
```bash
python app.py
```

**macOS / Linux**:
```bash
sudo python3 app.py
```

If port 80 is busy or you can't run as admin, edit the last line of `app.py` to `port=8080` and use `http://192.168.1.X:8080` instead.

## 📶 Network setup

1. Connect the laptop to the offline router's Wi-Fi.
2. Find the laptop's local IP:
   - Windows: `ipconfig` → look for *IPv4 Address* (e.g. `192.168.1.5`)
   - macOS/Linux: `ip addr` or `ifconfig`
3. (Recommended) In the router settings, give the laptop a **static/reserved IP** so the QR code never breaks.
4. Generate a QR code pointing to `http://192.168.1.X/` (any offline QR generator works).
5. Allow Python through the laptop firewall if prompted (Windows will ask on first run — choose *Private networks*).

## 🛡️ Anti-cheating logic

A student is blocked for 24 hours if **either**:
- their **IP address** already has a submission in the last 24h (checked in SQLite), **or**
- their browser carries a valid **signed cookie** (HttpOnly, cryptographically signed — cannot be forged or edited; survives router IP re-assignment).

Blocked students see the custom screen: **«عفواً، لقد قمت بتسجيل الحضور بالفعل اليوم!»**

## 👨‍🏫 Viewing the records (teacher)

On the laptop itself, open: `http://127.0.0.1/admin/list` — this page is only accessible from the server machine, never from student phones.

You can also inspect the raw database anytime:
```bash
sqlite3 attendance.db "SELECT * FROM students;"
```

## ⚠️ Known limitations

- Students sharing one IP (e.g. a phone hotspot) share one lock — rare on a normal router where each device gets its own IP.
- A tech-savvy student could clear cookies **and** change devices; the IP check catches the common case. For a classroom setting this hybrid approach is a solid deterrent.
