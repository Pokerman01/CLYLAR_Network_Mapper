# CLYLAR Network Scanner

## ภาษาไทย

CLYLAR Network Scanner เป็นเว็บแอปพลิเคชันที่พัฒนาด้วย Flask ใช้ตราสัญลักษณ์ของ NT (บริษัท โทรคมนาคมแห่งชาติ จำกัด (มหาชน)) ทำหน้าที่สแกนเครือข่ายด้วย nmap ค้นหาช่องโหว่ที่เป็นที่รู้จัก (CVE) ผ่านฐานข้อมูล NVD ตั้งเวลาสแกนซ้ำ สร้างรายงานรูปแบบ PDF และมีผู้ช่วย AI พร้อมคำสั่งเสียง หน้าจอใช้ภาษาไทย

> **กรุณาใช้เฉพาะกับเครือข่ายที่คุณเป็นเจ้าของหรือได้รับอนุญาตให้สแกนเท่านั้น** การสแกนเครือข่ายของผู้อื่นโดยไม่ได้รับอนุญาตอาจผิดกฎหมาย

### สิ่งที่ต้องมี

| | |
|---|---|
| Python 3.11 | สำหรับตัวแอปพลิเคชัน |
| [nmap](https://nmap.org/download.html) | ต้องอยู่ใน `PATH` บน Windows ให้ติดตั้ง **Npcap** ด้วย (ตัวติดตั้งของ nmap มีให้เลือก) การตรวจจับ OS และการสแกนบางแบบต้องใช้สิทธิ์ผู้ดูแลระบบ (Administrator / root) |
| Microsoft Edge หรือ Google Chrome | ใช้สร้างรายงาน PDF เท่านั้น (ระบบพิมพ์รายงานด้วยเบราว์เซอร์แบบไม่แสดงหน้าต่าง) |
| อินเทอร์เน็ต | หน้าเว็บโหลด Bootstrap ไอคอน และฟอนต์จาก CDN และการค้นหา CVE เรียกใช้ NVD |

### วิธีเริ่มใช้งาน

```bash
pip install -r requirements.txt
python app.py
```

เปิด <http://127.0.0.1:5000>

เมื่อเริ่มใช้งานครั้งแรก ระบบจะสร้างไฟล์ `instance/scanner.db` และบัญชีผู้ดูแลระบบ **`admin` / `admin123`** กรุณาเปลี่ยนรหัสผ่านทันที เพราะเป็นค่าเริ่มต้นสำหรับต้นแบบ ไม่เหมาะกับเครือข่ายที่ใช้ร่วมกัน และกรุณากำหนดค่า `SECRET_KEY` ของตนเองก่อนใช้งานนอกเครื่องส่วนตัว

```bash
set SECRET_KEY=a-long-random-string
```

### การตั้งค่าเพิ่มเติม (ไม่บังคับ)

- **ผู้ช่วย AI (Gemini)** ใส่คีย์ในไฟล์ `.env` (คัดลอกจาก `.env.example`) หรือวางที่หน้าตั้งค่า โดย Superadmin ตั้งคีย์ที่ใช้ร่วมกันได้ และผู้ดูแลระบบแต่ละคนตั้งคีย์ของตนเองได้ หากไม่มีคีย์ ผู้ช่วยยังตอบคำสั่งที่ระบบเข้าใจเองได้
- **ตัวถอดเสียง Whisper ในเครื่อง** ถอดเสียงคำสั่งเป็นข้อความบนเครื่องของคุณเอง โดยไม่ส่งเสียงไปยังผู้พัฒนาเบราว์เซอร์ ต้องดาวน์โหลดแยกต่างหากขนาดประมาณ 3 GB และตั้งค่าเพิ่มเติม ดูขั้นตอนใน **[docs/whisper-setup.md](docs/whisper-setup.md)** หากไม่ติดตั้ง ไมโครโฟนจะใช้ตัวถอดเสียงของเบราว์เซอร์แทน

---

## English

A Flask web app, branded for NT (National Telecom), that scans a network with `nmap`, looks up known vulnerabilities (CVEs) through the NVD, runs scans on a schedule, builds a PDF report, and has an AI assistant with voice commands. The interface is in Thai.

> **Use it only on networks you own or are authorised to scan.** Scanning other people's networks without permission can be illegal.

### What you need

| | |
|---|---|
| Python 3.11 | The app itself. |
| [nmap](https://nmap.org/download.html) | On the `PATH`. On Windows also install **Npcap** (the nmap installer offers it). OS detection and some scans need Administrator / root. |
| Microsoft Edge or Google Chrome | Only for the PDF report (it is printed by a headless browser). |
| Internet | The pages load Bootstrap, icons and fonts from CDNs, and CVE lookups call the NVD. |

### Run it

```bash
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>.

On the first run the app creates `instance/scanner.db` and an administrator account: **`admin` / `admin123`**. Change the password straight away (a prototype default, not for a shared network). Set your own session secret before running it anywhere other than your own computer:

```bash
set SECRET_KEY=a-long-random-string
```

### Optional settings

- **AI assistant (Gemini).** Put a key in a `.env` file (copy `.env.example`), or paste it on the Settings page (a superadmin sets the shared key, any admin can set their own). Without a key the assistant still answers the commands the system understands itself.
- **Local voice engine (Whisper).** Turns spoken commands into text on your own computer instead of sending audio to the browser vendor. It is a separate download of about 3 GB and needs its own setup: see **[docs/whisper-setup.md](docs/whisper-setup.md)**. Without it the microphone uses the browser's engine.