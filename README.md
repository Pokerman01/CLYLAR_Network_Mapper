# CLYLAR Network Scanner

## ภาษาไทย

CLYLAR Network Scanner เป็นเว็บแอปพลิเคชันที่พัฒนาด้วย Flask และใช้ตราสัญลักษณ์ของบริษัท โทรคมนาคมแห่งชาติ จำกัด (มหาชน) หรือ NT ความสามารถหลักได้แก่ สแกนเครือข่ายด้วย nmap ค้นหาช่องโหว่ที่เปิดเผยต่อสาธารณะ (CVE) จากฐานข้อมูล NVD ตั้งเวลาสแกนซ้ำ สร้างรายงาน PDF และผู้ช่วย AI ที่รองรับคำสั่งเสียง หน้าจอใช้ภาษาไทย

> **กรุณาใช้เฉพาะกับเครือข่ายที่คุณเป็นเจ้าของหรือได้รับอนุญาตให้สแกนเท่านั้น** การสแกนเครือข่ายของผู้อื่นโดยไม่ได้รับอนุญาตอาจมีความผิดตามกฎหมาย

### สิ่งที่ต้องมี

> [!IMPORTANT]
> **ใช้ Python 3.11 หรือ 3.13 เท่านั้น** Python 3.14 ยังใช้งานไม่ได้ (ผู้ทดสอบรายงานว่าแอปไม่ทำงาน) หากติดตั้ง Python 3.14 ไว้ กรุณาติดตั้งรุ่น 3.13 เพิ่ม และใช้รุ่นนั้นสร้างสภาพแวดล้อมเสมือน

| | |
|---|---|
| **Python 3.11 หรือ 3.13** | สำหรับเรียกใช้แอปพลิเคชัน ไม่รองรับ 3.14 (ดูหมายเหตุด้านบน) |
| [nmap](https://nmap.org/download.html) | ต้องเรียกใช้ได้จาก `PATH` ส่วนบน Windows ต้องติดตั้ง **Npcap** ด้วย (เลือกได้ในตัวติดตั้งของ nmap) การตรวจหา OS และการสแกนหลายประเภทต้องใช้สิทธิ์ผู้ดูแลระบบ จึงควรเรียกใช้แอปด้วยสิทธิ์ Administrator หรือ root หากไม่พบ nmap หน้างานสแกนจะแสดงคำเตือนและการสแกนจะไม่สำเร็จ |
| Microsoft Edge หรือ Google Chrome | ใช้สร้างรายงาน PDF เท่านั้น (ระบบพิมพ์รายงานด้วยเบราว์เซอร์แบบไม่แสดงหน้าต่าง) |
| อินเทอร์เน็ต | หน้าเว็บโหลด Bootstrap ไอคอน และฟอนต์จาก CDN ส่วนการค้นหา CVE ต้องเชื่อมต่อกับ NVD |

### วิธีเริ่มใช้งาน

แนะนำให้สร้างสภาพแวดล้อมเสมือน (virtual environment) ก่อนติดตั้งแพ็กเกจ

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux / macOS
pip install -r requirements.txt
python app.py
```

จากนั้นเปิด <http://127.0.0.1:5000> ในเบราว์เซอร์

เมื่อเรียกใช้ครั้งแรก ระบบจะสร้างฐานข้อมูล `instance/scanner.db` และบัญชีผู้ดูแลระบบสูงสุด (superadmin) ชื่อผู้ใช้ **`admin`** รหัสผ่าน **`admin123`** รหัสผ่านนี้เป็นค่าเริ่มต้นสำหรับทดลองใช้ กรุณาเปลี่ยนทันทีที่หน้าจัดการผู้ใช้งาน

ก่อนนำไปใช้งานจริงหรือใช้บนเครื่องที่ใช้ร่วมกับผู้อื่น กรุณากำหนด `SECRET_KEY` (คีย์สำหรับลงนามเซสชัน) เป็นค่าสุ่มของคุณเอง เนื่องจากค่าเริ่มต้นเปิดเผยอยู่ในซอร์สโค้ด วิธีที่ง่ายที่สุดคือเพิ่มบรรทัดต่อไปนี้ในไฟล์ `.env` ซึ่งใช้ได้กับทุกระบบปฏิบัติการ

```
SECRET_KEY=a-long-random-string
```

สร้างค่าสุ่มได้ด้วยคำสั่งนี้

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### การตั้งค่าเพิ่มเติม (ไม่บังคับ)

- **ผู้ช่วย AI (Gemini)** ใส่คีย์ในไฟล์ `.env` (คัดลอกจาก `.env.example`) หรือในหน้าตั้งค่า โดย superadmin กำหนดคีย์ที่ใช้ร่วมกันได้ และผู้ดูแลระบบแต่ละคนกำหนดคีย์ของตนเองได้ คีย์ในหน้าตั้งค่ามีลำดับก่อนไฟล์ `.env` หากไม่มีคีย์ คำสั่งเสียงและหน้าผู้ช่วยยังรับคำสั่งที่ระบบประมวลผลได้เอง เช่น สั่งสแกน ถามจำนวนอุปกรณ์ และเปิดหน้าต่าง ๆ
- **Whisper (ถอดเสียงเป็นข้อความในเครื่อง)** ถอดเสียงคำสั่งเป็นข้อความบนเครื่องของคุณเอง โดยไม่ส่งเสียงไปยังผู้พัฒนาเบราว์เซอร์ ต้องดาวน์โหลดโมเดลแยกต่างหาก (ประมาณ 3 GB) และตั้งค่าเพิ่มเติม ดูขั้นตอนใน **[docs/whisper-setup.md](docs/whisper-setup.md)** หากไม่ได้ติดตั้ง ระบบจะใช้ตัวถอดเสียงของเบราว์เซอร์แทน

---

## English

A Flask web app, branded for NT (National Telecom), that scans a network with `nmap`, looks up known vulnerabilities (CVEs) through the NVD, runs scans on a schedule, builds a PDF report, and has an AI assistant with voice commands. The interface is in Thai.

> **Use it only on networks you own or are authorised to scan.** Scanning other people's networks without permission can be illegal.

### What you need

> [!IMPORTANT]
> **Use Python 3.11 or 3.13 only.** Python 3.14 does not work yet (a tester reported that the app fails on it). If you have 3.14 installed, install 3.13 alongside it and create the virtual environment with that version.

| | |
|---|---|
| **Python 3.11 or 3.13** | The app itself. 3.14 is not supported (see the note above). |
| [nmap](https://nmap.org/download.html) | On the `PATH`. On Windows also install **Npcap** (the nmap installer offers it). OS detection and several scan types need Administrator / root, so run the app as Administrator (or root). Without nmap, the Tasks page shows a warning and scans fail. |
| Microsoft Edge or Google Chrome | Only for the PDF report (it is printed by a headless browser). |
| Internet | The pages load Bootstrap, icons and fonts from CDNs; CVE lookups need the NVD. |

### Run it

A virtual environment is recommended:

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux / macOS
pip install -r requirements.txt
python app.py
```

Then open <http://127.0.0.1:5000> in a browser.

On the first run the app creates `instance/scanner.db` and a superadmin account: **`admin`** / **`admin123`**. This is a default for trying the app out; change it at once on the User Management page.

Before real use, or on a shared machine, set your own random `SECRET_KEY` (it signs sessions; the default is public in the source). The simplest way, on any OS, is a line in `.env`:

```
SECRET_KEY=a-long-random-string
```

To generate a random value:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Optional settings

- **AI assistant (Gemini).** Put a key in a `.env` file (copy `.env.example`), or paste it on the Settings page (a superadmin sets the shared key, any admin can set their own). Settings-page keys take priority over `.env`. Without a key, voice commands and the Assistant page still handle what the system understands itself (scans, counts, opening pages).
- **Local voice engine (Whisper).** Turns spoken commands into text on your own computer instead of sending audio to the browser vendor. It is a separate download of about 3 GB and needs its own setup: see **[docs/whisper-setup.md](docs/whisper-setup.md)**. Without it the app uses the browser's engine.
