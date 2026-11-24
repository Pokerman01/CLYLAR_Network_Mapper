# CLYLAR Network Scanner

[ภาษาไทย](#ภาษาไทย) · [English](#english)

## ภาษาไทย

CLYLAR Network Scanner เป็นเว็บแอปพลิเคชันที่พัฒนาด้วย Flask ภายใต้อัตลักษณ์องค์กรของ NT บริษัท โทรคมนาคมแห่งชาติ จำกัด (มหาชน) แอปนี้สแกนเครือข่ายด้วย nmap ค้นหาช่องโหว่ที่เปิดเผยต่อสาธารณะ (CVE) จากฐานข้อมูล NVD ตั้งเวลาสแกนซ้ำ สร้างรายงาน PDF และมีผู้ช่วย AI ที่รองรับคำสั่งเสียง หน้าจอใช้งานได้ทั้งภาษาไทย (ค่าเริ่มต้น) และภาษาอังกฤษ พร้อมธีมสว่างและธีมมืด

> **กรุณาใช้เฉพาะกับเครือข่ายที่คุณเป็นเจ้าของหรือได้รับอนุญาตให้สแกนเท่านั้น** การสแกนเครือข่ายของผู้อื่นโดยไม่ได้รับอนุญาตอาจมีความผิดตามกฎหมาย

**สารบัญ:** [สิ่งที่ต้องมี](#สิ่งที่ต้องมี) · [เวอร์ชันที่ใช้ทดสอบ](#เวอร์ชันที่ใช้ทดสอบ) · [การติดตั้ง](#การติดตั้ง) · [การใช้งาน](#การใช้งาน) · [การตั้งค่าเพิ่มเติม](#การตั้งค่าเพิ่มเติม-ไม่บังคับ) · [AI ในเครื่อง](#การติดตั้งและใช้งาน-ai-ในเครื่อง) · [แก้ปัญหา](#แก้ปัญหาที่พบบ่อย)

### สิ่งที่ต้องมี

คู่มือนี้เขียนสำหรับ **Windows 10 หรือ 11** (ทดสอบบน Windows 11) ผู้ใช้ Linux และ macOS โปรดดู [หมายเหตุท้ายหัวข้อการติดตั้ง](#linux-และ-macos) ไม่จำเป็นต้องมีความรู้ด้านการเขียนโปรแกรม เพียงทำตามขั้นตอนทีละข้อ

> [!IMPORTANT]
> **ใช้ Python 3.11 หรือ 3.13 เท่านั้น** Python 3.14 ยังใช้งานไม่ได้ (ผู้ทดสอบรายงานว่าแอปไม่ทำงาน) คู่มือนี้ใช้ **Python 3.11.9** เป็นหลัก เพราะเป็นรุ่นที่ทดสอบขั้นตอนทั้งหมด หากติดตั้ง Python 3.14 ไว้แล้ว ให้ติดตั้ง 3.11.9 เพิ่มและใช้รุ่นนั้นในขั้นตอนที่ 5

| โปรแกรม | รุ่นที่แนะนำ | ใช้ทำอะไร | ดาวน์โหลด |
|---|---|---|---|
| Python | **3.11.9** (64-bit) | เรียกใช้แอปพลิเคชัน | [python.org/downloads/release/python-3119](https://www.python.org/downloads/release/python-3119/) |
| nmap (รวม Npcap) | **7.98** | สแกนเครือข่าย (การตรวจหา OS และการสแกนหลายประเภทต้องใช้สิทธิ์ผู้ดูแลระบบของ Windows จึงต้องเปิดแอปด้วยสิทธิ์นี้) | [nmap.org/download.html](https://nmap.org/download.html) |
| Git | 2.53 หรือใหม่กว่า | ดาวน์โหลดโค้ด (ไม่บังคับ ใช้ไฟล์ ZIP แทนได้) | [git-scm.com/downloads/win](https://git-scm.com/downloads/win) |
| Microsoft Edge หรือ Google Chrome | รุ่นใหม่ล่าสุด | เปิดหน้าเว็บของแอป และสร้างรายงาน PDF (Windows 10 และ 11 มี Edge อยู่แล้ว) | |
| อินเทอร์เน็ต | | หน้าเว็บของแอปโหลด Bootstrap ไอคอน และฟอนต์จากอินเทอร์เน็ต (CDN) และการค้นหา CVE ต้องเชื่อมต่อกับ NVD | |

ต้องใช้พื้นที่ดิสก์ประมาณ 1 GB สำหรับโปรแกรมทั้งหมดข้างต้นและแอป (ไม่รวม AI ในเครื่องและ Whisper ซึ่งเป็นส่วนเสริมและมีขนาดแยกต่างหาก)

### เวอร์ชันที่ใช้ทดสอบ

ตารางนี้แสดงเวอร์ชันที่ติดตั้งอยู่บนเครื่องพัฒนา ณ วันที่เขียนคู่มือ (23 พฤศจิกายน 2026) หากพบปัญหาหลังติดตั้งรุ่นที่ใหม่กว่า ให้ใช้รุ่นตามตารางนี้แทน

| รายการ | เวอร์ชัน |
|---|---|
| ระบบปฏิบัติการ | Windows 11 Home (รุ่น 10.0.26200) |
| Python | 3.11.9 |
| nmap | 7.98 |
| Npcap | 1.83 |
| Git | 2.53.0 |
| Microsoft Edge | 158.0.4370.33 |
| Ollama (ส่วนเสริม) | 0.40.17 |

แพ็กเกจ Python ที่ติดตั้งอยู่บนเครื่องพัฒนา

| แพ็กเกจ | เวอร์ชัน | แพ็กเกจ | เวอร์ชัน |
|---|---|---|---|
| Flask | 3.1.0 | APScheduler | 3.11.2 |
| Flask-Login | 0.6.3 | python-nmap | 0.7.1 |
| Flask-SQLAlchemy | 3.1.1 | requests | 2.33.1 |
| Flask-WTF | 1.3.0 | xhtml2pdf | 0.2.17 |
| Werkzeug | 3.1.3 | python-dotenv | 1.2.2 |
| psutil | 5.9.5 | websocket-client | 1.9.0 |

ไฟล์ `requirements.txt` ไม่ได้ระบุเวอร์ชัน ขั้นตอนที่ 5 จึงติดตั้งรุ่นล่าสุดของแต่ละแพ็กเกจ ซึ่งโดยปกติใช้งานได้ หากแอปมีปัญหาหลังติดตั้ง ให้ติดตั้งแพ็กเกจรุ่นตามตารางด้านบนด้วยคำสั่งด้านล่างแทน โดยพิมพ์ในโฟลเดอร์ของแอปหลังทำขั้นตอนที่ 5 เสร็จแล้ว คำสั่งนี้เป็นคำสั่งเดียวในบรรทัดเดียว และใช้กับ Python 3.11.9 เท่านั้น เพราะ `psutil` รุ่นนี้ยังไม่รองรับ Python 3.13

```bat
.venv\Scripts\python.exe -m pip install Flask==3.1.0 Flask-Login==0.6.3 Flask-SQLAlchemy==3.1.1 Flask-WTF==1.3.0 Werkzeug==3.1.3 APScheduler==3.11.2 python-nmap==0.7.1 requests==2.33.1 xhtml2pdf==0.2.17 python-dotenv==1.2.2 psutil==5.9.5 websocket-client==1.9.0
```

ยังไม่ได้ทดสอบบน Linux, macOS และ Python 3.13 ด้วยคู่มือนี้

### การติดตั้ง

**ก่อนเริ่ม: Command Prompt คืออะไร** Command Prompt คือหน้าต่างสีดำสำหรับพิมพ์คำสั่ง ทุกขั้นตอนในคู่มือนี้ใช้หน้าต่างนี้ (ไม่ใช่ PowerShell)

- **เปิด:** กดปุ่ม Windows พิมพ์ `cmd` แล้วกด Enter
- **คำสั่ง:** คำสั่งอยู่ในกรอบสีเทา ให้พิมพ์หรือคัดลอกทีละบรรทัด แล้วกด Enter ทุกครั้ง รอให้คำสั่งทำงานเสร็จ (เห็นเครื่องหมาย `>` กลับมา) ก่อนพิมพ์บรรทัดถัดไป
- **วางข้อความ:** คลิกขวาในหน้าต่าง หรือกด Ctrl+V
- **หยุดคำสั่งที่กำลังทำงาน:** กด Ctrl+C

| คำศัพท์ | ความหมาย |
|---|---|
| `PATH` | รายการโฟลเดอร์ที่ Windows ค้นหาโปรแกรมเมื่อคุณพิมพ์ชื่อคำสั่ง หากโปรแกรมไม่อยู่ในโฟลเดอร์เหล่านี้ Windows จะแสดงข้อความ "is not recognized" |
| สภาพแวดล้อมเสมือน (virtual environment) | โฟลเดอร์ `.venv` ที่เก็บแพ็กเกจของแอปนี้โดยเฉพาะ ไม่ปะปนกับโปรแกรม Python อื่นในเครื่อง |
| สิทธิ์ผู้ดูแลระบบของ Windows (Administrator) | สิทธิ์ระดับสูงของ Windows ซึ่งต้องกด Yes เพื่อยืนยันก่อนเปิดโปรแกรม ทั้งนี้ nmap ต้องใช้สิทธิ์นี้จึงจะตรวจ OS และ MAC ได้ครบ |
| เป้าหมายแบบ `/24` | `192.168.1.0/24` หมายถึงที่อยู่ 192.168.1.0 ถึง 192.168.1.255 รวม 256 ที่อยู่ ตัวเลขหลัง `/` ยิ่งน้อย เครือข่ายยิ่งใหญ่ |
| CVE | รหัสของช่องโหว่ที่เปิดเผยต่อสาธารณะ เช่น `CVE-2021-44228` |

**1. ติดตั้ง Python 3.11.9**

1. เปิด <https://www.python.org/downloads/release/python-3119/> เลื่อนลงไปที่หัวข้อ **Files** แล้วดาวน์โหลด **Windows installer (64-bit)**
2. เปิดไฟล์ที่ดาวน์โหลดมา จากนั้นที่ด้านล่างของหน้าต่างแรก **เลือกช่อง "Add python.exe to PATH" ก่อน** แล้วกด **Install Now** (หากไม่เลือกช่องนี้ คำสั่ง `python` จะใช้ไม่ได้)
3. เมื่อหน้าต่างแสดงข้อความ "Setup was successful" ให้กด **Close**
4. เปิด Command Prompt **หน้าต่างใหม่** (หน้าต่างที่เปิดไว้ก่อนติดตั้งจะยังไม่รู้จักคำสั่งใหม่) แล้วตรวจสอบด้วยคำสั่งนี้

```bat
python --version
```

ผลที่ถูกต้องคือ `Python 3.11.9` หากแสดงข้อความอื่น ดู [แก้ปัญหาที่พบบ่อย](#แก้ปัญหาที่พบบ่อย)

**2. ติดตั้ง nmap 7.98 และ Npcap**

1. เปิด <https://nmap.org/download.html> หัวข้อ **Microsoft Windows binaries** แล้วดาวน์โหลด **Latest stable release self-installer** (ไฟล์ชื่อ `nmap-7.98-setup.exe`)
2. เปิดไฟล์ กด **I Agree** และไม่ต้องเปลี่ยนรายการที่เลือกไว้ (รวม Npcap) แล้วกด **Install**
3. หน้าต่างติดตั้ง **Npcap** จะเปิดขึ้นระหว่างการติดตั้ง อย่าข้ามขั้นตอนนี้ ให้กด **I Agree** และ **Install** โดยไม่เปลี่ยนตัวเลือก เมื่อติดตั้งเสร็จให้กด **Finish** แล้วทำต่อในหน้าต่างของ nmap จนเสร็จ
4. เปิด Command Prompt **หน้าต่างใหม่** (หน้าต่างที่เปิดไว้ก่อนติดตั้งจะยังไม่รู้จักคำสั่งใหม่) แล้วตรวจสอบด้วยคำสั่งนี้

```bat
nmap --version
```

บรรทัดแรกต้องแสดง `Nmap version 7.98 ( https://nmap.org )` และมีคำว่า `Npcap` ในบรรทัด `Compiled with`

**3. ติดตั้ง Git (ข้ามได้หากใช้ไฟล์ ZIP)**

1. เปิด <https://git-scm.com/downloads/win> แล้วดาวน์โหลด **Git for Windows/x64 Setup**
2. เปิดไฟล์ กด **Next** ทุกหน้าโดยไม่เปลี่ยนตัวเลือก แล้วกด **Install** และ **Finish**
3. เปิด Command Prompt **หน้าต่างใหม่** แล้วตรวจสอบด้วยคำสั่งนี้

```bat
git --version
```

ต้องแสดง `git version 2.53.0` หรือใหม่กว่า

**4. ดาวน์โหลดโค้ดของแอป**

เมื่อเปิด Command Prompt จะเริ่มต้นที่โฟลเดอร์ผู้ใช้ของคุณ (เช่น `C:\Users\ชื่อผู้ใช้`) พิมพ์คำสั่งต่อไปนี้ทีละบรรทัด

```bat
mkdir clylar
cd clylar
git clone https://github.com/Pokerman01/CLYLAR_Network_Mapper.git
cd CLYLAR_Network_Mapper
dir
```

คำสั่ง `dir` ต้องแสดงไฟล์ เช่น `app.py` และ `requirements.txt` โฟลเดอร์ของแอปจะอยู่ที่ `C:\Users\ชื่อผู้ใช้\clylar\CLYLAR_Network_Mapper`

หากไม่ใช้ Git ให้เปิดหน้า GitHub ของโครงการ กด **Code** แล้วเลือก **Download ZIP** แตกไฟล์ (คลิกขวาที่ไฟล์ ZIP แล้วเลือก Extract All) จากนั้นเปิดโฟลเดอร์ที่มีไฟล์ `app.py` ใน File Explorer คลิกที่แถบที่อยู่ด้านบน พิมพ์ `cmd` แล้วกด Enter หน้าต่าง Command Prompt จะเปิดขึ้นในโฟลเดอร์นั้น จากนั้นข้ามไปขั้นตอนที่ 5

**5. สร้างสภาพแวดล้อมเสมือนและติดตั้งแพ็กเกจ**

พิมพ์ใน Command Prompt เดิม (ที่อยู่ในโฟลเดอร์ `CLYLAR_Network_Mapper`)

```bat
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

บรรทัดแรกใช้เวลาไม่กี่วินาที บรรทัดที่สองใช้เวลา 1 ถึง 3 นาที และจบด้วยบรรทัด `Successfully installed ...` ที่มีชื่อ Flask รวมอยู่ด้วย หากมีข้อความ "A new release of pip is available" ไม่ต้องดำเนินการใด ๆ คำสั่งในคู่มือนี้เรียกใช้ Python ในโฟลเดอร์ `.venv` โดยตรง จึงไม่ต้องเปิดใช้ (activate) สภาพแวดล้อมเสมือนก่อน

**6. สร้างไฟล์ตั้งค่า `.env` (แนะนำ)**

```bat
copy .env.example .env
.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
notepad .env
```

คำสั่งที่สองจะแสดงข้อความสุ่ม 64 ตัวอักษร ให้คัดลอกไว้ (ลากเมาส์เลือกข้อความแล้วกด Enter หน้าต่าง Command Prompt จะคัดลอกให้โดยไม่แสดงข้อความแจ้ง) คำสั่งที่สามจะเปิดไฟล์ `.env` ใน Notepad ให้เพิ่มบรรทัดใหม่ที่ท้ายไฟล์ พิมพ์ `SECRET_KEY=` แล้ววางข้อความสุ่มต่อท้ายโดยไม่เว้นวรรค ดังนี้

```
SECRET_KEY=ข้อความสุ่มที่คัดลอกมา
```

กด Ctrl+S เพื่อบันทึก แล้วปิด Notepad

`SECRET_KEY` คือคีย์ลับที่ระบบใช้ป้องกันข้อมูลการเข้าสู่ระบบไม่ให้ถูกปลอมแปลง ค่าเริ่มต้นเปิดเผยอยู่ในซอร์สโค้ด จึงควรตั้งค่าของตนเองก่อนใช้งานจริงหรือก่อนใช้บนเครื่องที่ใช้ร่วมกับผู้อื่น หากทดลองบนเครื่องส่วนตัวเท่านั้น สามารถข้ามขั้นตอนนี้ได้

**7. เริ่มแอปด้วยสิทธิ์ผู้ดูแลระบบ**

1. ปิดหน้าต่าง Command Prompt เดิม
2. กดปุ่ม Windows พิมพ์ `cmd` คลิกขวาที่ **Command Prompt** แล้วเลือก **Run as administrator** (Windows ภาษาไทย: **เรียกใช้ในฐานะผู้ดูแลระบบ**) กด **Yes** (**ใช่**) เมื่อ Windows ถามยืนยัน แถบชื่อของหน้าต่างที่เปิดขึ้นต้องมีคำว่า **Administrator**
3. พิมพ์คำสั่งต่อไปนี้ทีละบรรทัด

```bat
cd /d "%USERPROFILE%\clylar\CLYLAR_Network_Mapper"
.venv\Scripts\python.exe app.py
```

หากดาวน์โหลดเป็นไฟล์ ZIP ให้เปลี่ยนตำแหน่งหลัง `cd /d` เป็นโฟลเดอร์ที่มีไฟล์ `app.py` (ใส่เครื่องหมายคำพูดครอบตำแหน่งนั้น)

เมื่อเริ่มสำเร็จ หน้าต่างจะแสดงบรรทัด `Running on http://127.0.0.1:5000` และ `Press CTRL+C to quit` (ข้อความเตือนว่า "This is a development server" เป็นเรื่องปกติ) **ปล่อยหน้าต่างนี้เปิดไว้** เพราะแอปทำงานอยู่ในหน้าต่างนี้ หากปิดหน้าต่าง แอปจะหยุด

> หากไม่ใช้สิทธิ์ผู้ดูแลระบบ แอปยังเปิดได้ แต่ผลตรวจจับ OS และ MAC จะไม่ครบ และการสแกนบางประเภทอาจไม่สำเร็จ หน้างานสแกนจะแสดงแถบสีเหลืองเตือนเรื่องนี้ แอปเปิดให้ใช้งานได้เฉพาะจากเครื่องที่ใช้สแกนเท่านั้น (`127.0.0.1`) เครื่องอื่นในเครือข่ายจะเข้าใช้งานไม่ได้

**8. เข้าสู่ระบบครั้งแรก**

1. เปิด Microsoft Edge หรือ Chrome แล้วไปที่ <http://127.0.0.1:5000>
2. เข้าสู่ระบบด้วยชื่อผู้ใช้ **`admin`** รหัสผ่าน **`admin123`** (ระบบสร้างบัญชีผู้ดูแลระบบสูงสุดและฐานข้อมูล `instance/scanner.db` ให้เองเมื่อเริ่มครั้งแรก)
3. **เปลี่ยนรหัสผ่านทันที** คลิกวงกลมตัวอักษรที่มุมขวาบน เลือก **ผู้ใช้งานระบบ** หาแถวของ `admin` แล้วกด **รีเซ็ตรหัสผ่าน** รหัสผ่านเริ่มต้นเป็นค่าสำหรับทดลองใช้เท่านั้น

**9. ทดสอบว่าใช้งานได้**

ทดลองสแกนเครื่องของคุณเอง ซึ่งปลอดภัยและเสร็จเร็ว

1. เลือก **งานสแกน** ในเมนูด้านซ้าย แล้วกดปุ่ม **สแกนใหม่**
2. ตั้งชื่องาน เช่น `ทดสอบ` ใส่เป้าหมายเป็น `127.0.0.1` เลือกประเภท **สแกนแบบเร็ว (Fast Scan)** แล้วกด **เริ่มสแกน**
3. ภายในไม่กี่วินาที สถานะต้องเปลี่ยนเป็น **เสร็จสิ้น** จากนั้นกดปุ่ม **ตรวจสอบ** ในแถวของงานเพื่อเปิดหน้าผลสแกน ซึ่งต้องพบอุปกรณ์ 1 เครื่อง (เครื่องของคุณเอง)

หากสแกนไม่สำเร็จหรือมีแถบสีเหลืองเตือน ดู [แก้ปัญหาที่พบบ่อย](#แก้ปัญหาที่พบบ่อย)

**ครั้งต่อไปที่ต้องการใช้งาน** ไม่ต้องติดตั้งซ้ำ เพียงเปิด Command Prompt ด้วยสิทธิ์ผู้ดูแลระบบ (ตามขั้นตอนที่ 7) แล้วพิมพ์คำสั่งสองบรรทัดเดิม

```bat
cd /d "%USERPROFILE%\clylar\CLYLAR_Network_Mapper"
.venv\Scripts\python.exe app.py
```

กด Ctrl+C ในหน้าต่างนั้นเพื่อหยุดแอป ข้อมูลทั้งหมดเก็บอยู่ในโฟลเดอร์ `instance` และไม่หายเมื่อปิดแอป

**อัปเดตเป็นรุ่นใหม่** (ใช้ได้เฉพาะเมื่อดาวน์โหลดด้วย Git) ปิดแอปก่อน (Ctrl+C) แล้วพิมพ์ในโฟลเดอร์ของแอป

```bat
git pull
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

#### Linux และ macOS

ขั้นตอนต่อไปนี้ **ยังไม่ได้ทดสอบ** ต้องมี Python 3.11, nmap และ Git

```bash
sudo apt install python3 python3-venv git nmap      # Debian / Ubuntu
brew install python@3.11 nmap git                   # macOS (Homebrew)
git clone https://github.com/Pokerman01/CLYLAR_Network_Mapper.git
cd CLYLAR_Network_Mapper
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
sudo .venv/bin/python app.py
```

จากนั้นเปิด <http://127.0.0.1:5000> การสร้างรายงาน PDF ต้องมี Google Chrome หรือ Microsoft Edge ในเครื่อง

### การใช้งาน

#### สแกนครั้งแรก

1. เข้าสู่ระบบ แล้วเลือก **งานสแกน** ในเมนูด้านซ้าย
2. กดปุ่ม **สแกนใหม่** ตั้งชื่องาน กรอก **เป้าหมาย** เช่น `192.168.1.0/24` (ทั้งเครือข่าย 256 ที่อยู่) หรือ `192.168.1.10` (อุปกรณ์เดียว) แล้วเลือกประเภทการสแกน
3. กด **เริ่มสแกน** ระบบจะรับงานเข้าคิวและทำงานเบื้องหลัง คุณสามารถเปลี่ยนไปหน้าอื่นระหว่างรอได้ เมื่อสแกนเสร็จ จะมีข้อความแจ้งที่มุมขวาล่าง
4. ในหน้างานสแกน กดลูกศรหน้าแถวของงานเพื่อดูรายละเอียด เช่น คำสั่ง nmap ที่ใช้จริง ความคืบหน้า และผลสรุป กดปุ่ม **หยุด** เพื่อยกเลิกงานที่รอคิวหรือกำลังทำงาน (ระบบจะหยุดการทำงานของ nmap ทันที)
5. เมื่อสแกนเสร็จ กดปุ่ม **ตรวจสอบ** ในแถวของงานเพื่อเปิดหน้าผลสแกน

ระบบสแกนได้พร้อมกันครั้งละ 2 งาน งานอื่นจะรอคิว งานที่ใช้เวลานานเกินกำหนดจะหยุดเองและแสดงสถานะ **ไม่สำเร็จ** (ค่าเริ่มต้น: ค้นหาอุปกรณ์ 1 ชั่วโมง สแกนแบบเร็ว 2 ชั่วโมง สแกนแบบละเอียด สแกนช่องโหว่ และสแกนแบบกำหนดเอง 4 ชั่วโมง ส่วนตัวเลือกสแกนทุกพอร์ต สแกนแบบนุ่มนวล และสแกนพอร์ต UDP จะเพิ่มเวลาเป็น 6 ถึง 8 ชั่วโมง)

#### ประเภทการสแกน

| ประเภท | ใช้เมื่อ |
|---|---|
| ค้นหาอุปกรณ์ (Discovery) | ต้องการทราบว่ามีอุปกรณ์ใดออนไลน์อยู่บ้าง เร็วที่สุดแต่ไม่สแกนพอร์ต และอ่านชื่ออุปกรณ์จาก mDNS / SSDP ได้ |
| สแกนแบบเร็ว (Fast Scan) | ตรวจพอร์ตที่พบบ่อย 100 พอร์ต พร้อมเวอร์ชันของบริการและ OS |
| สแกนแบบละเอียด (Intense Scan) | ตรวจ 1,000 พอร์ตที่พบบ่อยอย่างละเอียด รวมถึง OS และเส้นทาง (traceroute) ใช้เวลานานกว่า |
| สแกนช่องโหว่ (Vulnerability Scan, CVE) | สแกนละเอียดแล้วค้นหา CVE จาก NVD ตามชื่อและเวอร์ชันของบริการที่พบในแต่ละพอร์ตที่เปิด |
| สแกนแบบกำหนดเอง (Custom) | กำหนดตัวเลือกของ nmap เองจากรายการที่ระบบอนุญาตเท่านั้น (ใช้ `--script` หรือบันทึกไฟล์ไม่ได้) |
| นำเข้าไฟล์ XML | นำไฟล์ผลสแกนของ nmap (`-oX`) ที่สแกนจากเครื่องอื่นมาแสดงในระบบ (แท็บ **นำเข้า** ในหน้างานสแกน) |

**ตัวเลือกขั้นสูง** ในหน้าต่างสร้างงานสแกนใหม่ ได้แก่ ความเร็วในการสแกน, ข้ามการ ping (`-Pn`), สแกนทุกพอร์ต (1-65535), ไม่ค้นหาชื่ออุปกรณ์ผ่าน DNS (`-n`), ตรวจหาอุปกรณ์ที่ไม่ตอบ ping, สแกนแบบนุ่มนวล และสแกนพอร์ต UDP ที่พบบ่อยเพิ่มเติม (บางตัวเลือกแสดงเฉพาะบางประเภทการสแกน) เปิดสวิตช์ **แสดงคำสั่ง** ที่มุมขวาบนของหน้าต่างเพื่อดูคำสั่ง nmap ที่ระบบจะใช้จริง

> **หมายเหตุเรื่องผล CVE:** ระบบค้นหา CVE ด้วยคำค้นจากชื่อและเวอร์ชันของบริการ ไม่ใช่การจับคู่แบบ CPE และเก็บไว้สูงสุด 5 รายการต่อบริการ จึงอาจมีผลที่ไม่ตรงกับอุปกรณ์จริง ควรตรวจสอบก่อนนำไปสรุป พอร์ตที่ค้นหาไม่สำเร็จหรือไม่มีข้อมูลให้ค้นหาจะแสดงว่า "ยังไม่ทราบ" ไม่ใช่ "ไม่พบ"

#### การดูผล

| เมนู | สิ่งที่ได้ |
|---|---|
| แดชบอร์ด | ภาพรวม: จำนวนอุปกรณ์ จำนวนพอร์ตที่เปิด จำนวน CVE สถานะงานสแกน และสิ่งที่เปลี่ยนไปจากการสแกนครั้งก่อน เลือกแสดงหรือซ่อนแต่ละส่วนได้ด้วยปุ่ม **ปรับแต่งหน้านี้** ข้างวันที่ |
| ประวัติการสแกน | งานสแกนทั้งหมด ค้นหาได้ด้วยที่อยู่ IP, เป้าหมาย หรือชื่องาน และใช้ตัวกรองขั้นสูงได้ (เช่น หางานที่พบพอร์ต 445 และ OS ที่มีคำว่า windows บนอุปกรณ์เดียวกัน) |
| อุปกรณ์ | รายการอุปกรณ์ที่พบทั้งหมด คลิกที่อยู่ IP เพื่อเปิดหน้าอุปกรณ์ ซึ่งรวมพอร์ต CVE และประวัติของอุปกรณ์นั้นจากทุกการสแกน |
| ช่องโหว่ | CVE ที่พบ กรองตามระดับความรุนแรง ดูภาพรวมจำนวนพอร์ตที่ตรวจ CVE แล้ว และอุปกรณ์ที่ได้รับผลกระทบ |
| แผนผังเครือข่าย | แผนผังของอุปกรณ์รวมจากหลายการสแกน ลากย้ายตำแหน่งได้ เลือกการจัดกลุ่ม (/24, /16 หรือไม่จัดกลุ่ม) ได้จากปุ่มฟันเฟืองที่มุมขวาบนของแผนผัง และค้นหาหรือกรองอุปกรณ์ได้จากแถบด้านซ้าย |
| รายงาน | ดาวน์โหลดรายงานสรุปเป็น PDF (A4 แนวตั้งหรือแนวนอน) หรือส่งออก CSV (การสร้าง PDF ต้องมี Edge หรือ Chrome ในเครื่อง) |

#### สั่งสแกนซ้ำและตั้งเวลา

- **สแกนซ้ำ:** ในหน้างานสแกน กดปุ่มสแกนซ้ำ (ไอคอนลูกศรวน) ในแถวของงานที่เสร็จแล้ว ระบบจะเปิดหน้าต่างที่ใส่ค่าเดิมไว้ให้
- **สแกนเจาะลึก:** ในหน้าผลสแกน กดปุ่มสแกนเจาะลึกในแถวของอุปกรณ์ เพื่อสแกนเฉพาะอุปกรณ์นั้นอย่างละเอียด
- **ตั้งเวลา:** ในหน้าต่างสร้างงานสแกนใหม่ เปิดส่วน **ตั้งเวลา** เพื่อให้สแกนซ้ำตามรอบ พิมพ์เวลาในช่องได้โดยตรง เช่น `14:30` หรือ `2pm` แล้วกด **บันทึกการตั้งเวลา** การสแกนตามเวลาจะทำงานเฉพาะเมื่อแอปทำงานอยู่ (หน้าต่าง Command Prompt ของแอปยังเปิดอยู่)

#### ผู้ช่วยและคำสั่งเสียง

- เมนู **ผู้ช่วย** เป็นหน้าแชท พิมพ์คำสั่ง เช่น "สแกน 192.168.1.10" ถามข้อมูล เช่น "มีกี่อุปกรณ์" หรือสั่งเปิดหน้า เช่น "เปิดหน้ารายงาน" ระบบประมวลผลคำสั่งสแกน คำถามเกี่ยวกับข้อมูล และการเปิดหน้าได้เอง โดยไม่ใช้ AI ส่วนคำถามอื่นจะส่งต่อให้ AI (ต้องตั้งค่า ดู [การตั้งค่าเพิ่มเติม](#การตั้งค่าเพิ่มเติม-ไม่บังคับ))
- ระบบจะเริ่มสแกนตามคำสั่งก็ต่อเมื่อคุณกด **ยืนยันและเริ่มสแกน** ที่การ์ดแล้ว เว้นแต่คุณเปิดสวิตช์ **สแกนทันที** (ใช้ได้กับเครือข่ายภายในที่มีขนาดไม่เกิน /24 หรือ 256 ที่อยู่เท่านั้น) AI ไม่สามารถเริ่มสแกนเองได้ แม้ AI เสนอคำสั่งสแกนในหน้าต่างแชทที่เปิดจากปุ่มลอย ก็ต้องกดยืนยันที่การ์ดเช่นเดียวกัน
- ปุ่มลอยที่มุมขวาล่างมีเมนูลัด 3 รายการ ได้แก่ **แชท** **สั่งด้วยเสียง** และ **สแกนด่วน** ส่วนเมนู **เสียง** เป็นหน้าเต็มสำหรับสั่งด้วยเสียง การสั่งด้วยเสียงต้องใช้ Chrome หรือ Edge และเปิดแอปผ่าน `127.0.0.1`, `localhost` หรือ HTTPS
- ระหว่างรอคำตอบของ AI คุณเปลี่ยนไปหน้าอื่นได้ คำตอบจะแสดงเมื่อกลับมาที่แชทนั้น ระหว่างรอสามารถกด **หยุด** ได้ และหากไม่ได้รับคำตอบ สามารถกด **ลองอีกครั้ง** ได้

#### บทบาทของผู้ใช้

| บทบาท | สิทธิ์ |
|---|---|
| ผู้ดูแลระบบสูงสุด (superadmin) | จัดการผู้ใช้ทุกคน ตั้งค่าคีย์ AI ที่ใช้ร่วมกัน เลือกโมเดล AI และเปิดหรือปิดการใช้ AI |
| ผู้ดูแลระบบ (admin) | สั่งสแกน ตั้งเวลา ใช้ผู้ช่วย และสร้างบัญชีผู้ใช้ (user) ของตนเอง เห็นเฉพาะงานสแกนที่ตนเองสั่ง |
| ผู้ใช้ (user) | ดูผลสแกนของผู้ดูแลระบบที่สร้างบัญชีให้ สั่งสแกนไม่ได้และใช้ผู้ช่วยไม่ได้ |

#### ภาษา ธีม และการตั้งค่าส่วนตัว

ปุ่มสลับธีมสว่าง / มืด และภาษาไทย / อังกฤษอยู่ที่แถบด้านบน ระบบจะบันทึกค่าที่เลือกไว้กับบัญชีของคุณ รายงาน PDF เป็นภาษาไทยและธีมสว่างเสมอ

### การตั้งค่าเพิ่มเติม (ไม่บังคับ)

- **ผู้ช่วย AI ออนไลน์ (Gemini)** ใส่คีย์ต่อจาก `GOOGLE_API_KEY=` ในไฟล์ `.env` (ที่สร้างในขั้นตอนที่ 6) หรือในหน้าตั้งค่า โดยผู้ดูแลระบบสูงสุด (superadmin) กำหนดคีย์ที่ใช้ร่วมกันได้ และผู้ดูแลระบบแต่ละคนกำหนดคีย์ของตนเองได้ หากตั้งคีย์ไว้ทั้งสองที่ ระบบจะใช้คีย์ในหน้าตั้งค่า ขอรับคีย์ได้ที่ <https://aistudio.google.com/app/apikey>
  - ผู้ดูแลระบบสูงสุดเลือกโมเดล Gemini ได้จากรายการในหน้าตั้งค่า รายการนี้แสดงโมเดลที่คีย์ของระบบใช้ได้ จึงต้องตั้งคีย์ก่อน และเมื่อเปลี่ยนจากโมเดลในเครื่องมาใช้ Gemini ระบบจะแจ้งเตือนก่อนว่าคำถามจะถูกส่งไปยัง Google
  - AI เห็นตัวเลขสรุปครบทุกรายการ แต่เห็นรายการละเอียดของอุปกรณ์ ช่องโหว่ และงานสแกนเพียงบางส่วน หากต้องการข้อมูลเฉพาะรายการ ให้ระบุที่อยู่ IP หรือรหัส CVE ในคำถาม
  - หากไม่มีคีย์ คำสั่งเสียงและหน้าผู้ช่วยยังรับคำสั่งที่ระบบประมวลผลได้เอง เช่น สั่งสแกน ถามจำนวนอุปกรณ์ และเปิดหน้าอื่น ๆ ของแอป
- **คีย์ NVD (ค้นหา CVE)** ใช้กับการสแกนช่องโหว่ และไม่บังคับ หากไม่มีคีย์ ระบบยังค้นหาได้แต่ช้าลง เพราะ NVD อนุญาตเพียง 5 คำขอใน 30 วินาที (ระบบจึงเว้นช่วงระหว่างคำขอประมาณ 6.5 วินาที) ขอคีย์ฟรีได้ที่ <https://nvd.nist.gov/developers/request-an-api-key> NVD จะส่งคีย์ทางอีเมล และต้องกดลิงก์ยืนยันในอีเมลก่อนจึงจะใช้ได้ จากนั้นใส่คีย์ต่อจาก `NVD_API_KEY=` ในไฟล์ `.env` หรือใส่ที่หน้า **ตั้งค่า** ในการ์ด **การค้นหา CVE (NVD)** (เฉพาะผู้ดูแลระบบสูงสุด) หากตั้งไว้ทั้งสองที่ ระบบจะใช้คีย์ในหน้าตั้งค่า
- **AI ในเครื่อง (Ollama + Typhoon)** ตอบคำถามด้วยโมเดลที่ทำงานบนเครื่องของคุณแทน Gemini ข้อมูลจึงไม่ออกนอกเครื่อง ดูขั้นตอนทั้งหมดที่หัวข้อ [การติดตั้งและใช้งาน AI ในเครื่อง](#การติดตั้งและใช้งาน-ai-ในเครื่อง)
- **Whisper (ถอดเสียงเป็นข้อความในเครื่อง)** ถอดเสียงคำสั่งเป็นข้อความบนเครื่องของคุณเอง โดยไม่ส่งเสียงไปยังผู้พัฒนาเบราว์เซอร์ ต้องดาวน์โหลดโมเดลแยกต่างหาก (ประมาณ 3 GB) และตั้งค่าเพิ่มเติม ดูขั้นตอนใน **[docs/whisper-setup.md](docs/whisper-setup.md)** หากไม่ได้ติดตั้ง ระบบจะใช้ตัวถอดเสียงของเบราว์เซอร์แทน
- **ตัวแปรสภาพแวดล้อมอื่น ๆ** (เพิ่มเป็นบรรทัดใหม่ในไฟล์ `.env` แล้วเริ่มแอปใหม่) `CLYLAR_BROWSER` (ตำแหน่งไฟล์เต็มของ Edge หรือ Chrome หากระบบหาไม่พบ), `CLYLAR_SCAN_TIME_LIMIT` (เวลาจำกัดของการสแกนเป็นวินาที แทนค่าเริ่มต้นทั้งหมด ใส่ `0` เพื่อปิดการจำกัด), `MAC_LOOKUP_ONLINE=1` (ให้ค้นหาผู้ผลิตจาก MAC ออนไลน์เมื่อฐานข้อมูลของ nmap ไม่มีข้อมูล ซึ่งจะส่งส่วนแรกของ MAC ไปยังบริการภายนอก)

### การติดตั้งและใช้งาน AI ในเครื่อง

ผู้ช่วยตอบคำถามได้ด้วยโมเดล **Typhoon 2.5 (Qwen3 4B)** ที่ทำงานบนเครื่องของคุณผ่านโปรแกรม [Ollama](https://ollama.com) แทน Gemini ระบบจะไม่ส่งข้อมูลสรุปที่แนบไปกับคำถามออกนอกเครื่องที่ใช้สแกน และไม่ต้องใช้คีย์ API การตั้งค่านี้ไม่บังคับ

| | |
|---|---|
| ระบบปฏิบัติการ | Windows, macOS หรือ Linux ที่ Ollama รองรับ |
| พื้นที่ดิสก์ | ประมาณ 2.5 GB สำหรับโมเดล และอีกประมาณ 3 GB สำหรับโปรแกรม Ollama บน Windows |
| หน่วยความจำ | ประมาณ 4 ถึง 4.5 GB ขณะโมเดลทำงาน (รวม RAM และหน่วยความจำของการ์ดจอ) |
| การ์ดจอ (GPU) | ไม่บังคับ การ์ดจอ NVIDIA ช่วยให้ตอบเร็วขึ้น หากไม่มีจะใช้ CPU ซึ่งช้ากว่า |
| อินเทอร์เน็ต | ใช้เฉพาะตอนดาวน์โหลด Ollama และโมเดล หลังจากนั้นใช้งานแบบออฟไลน์ได้ |

**ขั้นตอนการติดตั้ง**

1. **ติดตั้ง Ollama** (รุ่นที่ทดสอบ 0.40.17) ดาวน์โหลดตัวติดตั้ง Windows จาก <https://ollama.com/download> เปิดไฟล์ แล้วกด **Install** ตัวติดตั้งจะเปิด Ollama ให้ทำงานเบื้องหลังที่ `http://127.0.0.1:11434` (มีไอคอนที่มุมขวาล่างของแถบงาน) เปิด Command Prompt หน้าต่างใหม่แล้วตรวจสอบด้วยคำสั่ง

   ```bash
   ollama --version
   ```

2. **ดาวน์โหลดโมเดล** ใช้เวลาหลายนาทีขึ้นอยู่กับความเร็วอินเทอร์เน็ต

   ```bash
   ollama pull scb10x/typhoon2.5-qwen3-4b
   ```

   ตรวจสอบว่าโมเดลอยู่ในรายการ

   ```bash
   ollama list
   ```

   หากแสดงข้อความ `could not connect to a running Ollama instance` แสดงว่า Ollama ยังไม่ทำงาน ให้เปิดโปรแกรม **Ollama** จากเมนู Start แล้วพิมพ์คำสั่งเดิมอีกครั้ง

3. **เลือกใช้ในแอป** เข้าสู่ระบบด้วยบัญชีผู้ดูแลระบบสูงสุด (superadmin) ซึ่งเป็นบัญชีเดียวที่เปลี่ยนค่านี้ได้ เปิดหน้า **ตั้งค่า** ไปที่การ์ด **ผู้ช่วย AI** แล้วเลือก **ในเครื่อง (Typhoon)** ในช่อง **AI ที่ใช้ตอบ**
4. **ทดสอบ** กด **ทดสอบการเชื่อมต่อ** ระบบจะแจ้งว่าเชื่อมต่อ Ollama ได้หรือไม่ และพบโมเดลที่ตั้งไว้หรือไม่ การทดสอบไม่เรียกใช้โมเดลและไม่โหลดโมเดลเข้าหน่วยความจำ
5. **ใช้งาน** ถามผู้ช่วยตามปกติที่หน้า **ผู้ช่วย** หรือปุ่มลอย คำตอบจะมีป้าย **AI ในเครื่อง** กำกับ และเมื่อวางเมาส์บนแถบสถานะของแชท จะมีคำอธิบายว่าคำถามไม่ออกนอกเครื่องที่ใช้สแกน หากคำตอบใช้เวลานาน กดปุ่ม **หยุด** ได้ ระบบจะหยุดการทำงานของโมเดลทันที

**การปรับแต่ง** กด **ตั้งค่าโมเดล** ในการ์ดเดียวกัน

| ช่อง | ความหมาย |
|---|---|
| ที่อยู่เซิร์ฟเวอร์ Ollama | ค่าเริ่มต้น `http://127.0.0.1:11434` ต้องชี้ไปที่เครื่องที่ใช้สแกนเท่านั้น (`127.0.0.1` หรือ `localhost`) ระบบไม่รับที่อยู่ของเครื่องอื่น |
| ชื่อโมเดล | ค่าเริ่มต้น `scb10x/typhoon2.5-qwen3-4b` รายการโมเดลที่ติดตั้งแล้วจะแสดงให้เลือก ใช้โมเดลอื่นได้ แต่ได้ทดสอบกับ Typhoon เท่านั้น |
| เลเยอร์ที่ใช้ GPU | ค่าเริ่มต้น 20 เลเยอร์ เว้นว่างเพื่อให้ Ollama กำหนดเอง ลดค่านี้หากหน่วยความจำของการ์ดจอไม่พอ โดยเฉพาะเมื่อเปิด Whisper พร้อมกัน (ยังไม่ได้ทดสอบการใช้ทั้งสองพร้อมกัน) |

**สิ่งที่ควรทราบ**

- **ไม่สลับไปใช้ Gemini เอง** หากโมเดลในเครื่องทำงานไม่ได้ ระบบจะแจ้งข้อผิดพลาดและระบุว่าไม่ได้ส่งคำถามไปยัง Gemini หากต้องการใช้ Gemini ให้เปลี่ยนช่อง **AI ที่ใช้ตอบ** กลับเป็น **ออนไลน์ (Gemini)**
- **สวิตช์ เปิดใช้งาน** ในการ์ดเดียวกันใช้ปิด AI ได้ทั้งสองแบบ คำสั่งที่ระบบประมวลผลเอง (สั่งสแกน ถามจำนวน เปิดหน้า) ใช้ได้เสมอโดยไม่ต้องมี AI
- **การถอดเสียงพูดไม่เปลี่ยน** ยังใช้ Whisper หรือตัวถอดเสียงของเบราว์เซอร์ตามเดิม โมเดลนี้ตอบเฉพาะข้อความ
- **ความเร็ว** คำถามแรกช้าเพราะต้องโหลดโมเดล ตัวอย่างบนโน้ตบุ๊กที่มีการ์ดจอ RTX 3060 (6 GB) คือประมาณ 85 วินาที จากนั้นประมาณ 5 ถึง 13 วินาทีต่อคำตอบ เครื่องของคุณอาจต่างออกไป เมื่อไม่ได้ใช้งานประมาณ 5 นาที Ollama จะนำโมเดลออกจากหน่วยความจำ คำถามถัดไปจึงช้าอีกครั้ง ระบบรอคำตอบได้สูงสุด 4 นาที
- **ตอบทีละคำถาม** คำถามที่ส่งไปยังโมเดลในเครื่องจะเข้าคิวและตอบทีละคำถาม
- **สถิติการใช้งาน** ตารางการใช้งานในหน้าตั้งค่านับคำถามที่ตอบด้วยโมเดลในเครื่องแยกบรรทัด และไม่นับเป็นโทเคนของ Gemini

**การลบ** หากไม่ต้องการใช้อีก ให้ลบโมเดลด้วย `ollama rm scb10x/typhoon2.5-qwen3-4b` เพื่อคืนพื้นที่ประมาณ 2.5 GB หากต้องการเก็บโมเดลไว้ในไดรฟ์อื่น ให้กำหนดตัวแปร `OLLAMA_MODELS` ตามเอกสารของ Ollama

**ปัญหาที่พบบ่อยของ AI ในเครื่อง**

| อาการ | สาเหตุและวิธีแก้ |
|---|---|
| ทดสอบการเชื่อมต่อไม่ผ่าน | Ollama ยังไม่ทำงาน หรือเพิ่งเริ่มทำงาน หลังเปิดเครื่องอาจใช้เวลา 1 ถึง 2 นาที (หน้าตั้งค่าจะลองซ้ำเองประมาณ 2 นาที) หากยังไม่ได้ ให้เปิดโปรแกรม Ollama (หรือรัน `ollama serve`) ตรวจสอบค่าในช่อง **ที่อยู่เซิร์ฟเวอร์ Ollama** และกด **ดูวิธีแก้ไข** ข้างข้อความเพื่อดูขั้นตอนทีละข้อ |
| แจ้งว่าไม่พบโมเดล | ยังไม่ได้ดาวน์โหลดโมเดล หรือชื่อโมเดลในช่องไม่ตรงกับ `ollama list` |
| ตอบช้ามาก | ตรวจด้วย `ollama ps` ว่าโมเดลใช้การ์ดจอบางส่วนหรือไม่ หากใช้เฉพาะ CPU จะช้า ให้เพิ่มเลเยอร์ที่ใช้ GPU หากหน่วยความจำการ์ดจอเหลือพอ |
| Ollama หรือแอปแจ้งว่าหน่วยความจำไม่พอ | ลดเลเยอร์ที่ใช้ GPU ลง หรือปิด Whisper ชั่วคราว |
| บันทึกที่อยู่ไม่ได้ | ที่อยู่ต้องชี้ไปที่เครื่องที่ใช้สแกนเท่านั้น (`127.0.0.1` หรือ `localhost`) ใช้ที่อยู่ของเครื่องอื่นไม่ได้ |

### แก้ปัญหาที่พบบ่อย

| อาการ | สาเหตุและวิธีแก้ |
|---|---|
| แสดงข้อความ `'python' is not recognized` หรือเปิด Microsoft Store | ไม่ได้เลือกช่อง "Add python.exe to PATH" ตอนติดตั้ง ให้ถอนการติดตั้ง Python (ตั้งค่า > แอป) แล้วติดตั้งใหม่พร้อมเลือกช่องนี้ หากเปิด Microsoft Store ขึ้นมา ให้ค้นหา "App execution aliases" (Windows ภาษาไทย: "นามแฝงการดำเนินการของแอป") ในช่องค้นหาของ Windows แล้วปิดรายการ `python.exe` |
| `python --version` ไม่ใช่ 3.11.9 | มี Python หลายรุ่นในเครื่อง ให้ติดตั้ง 3.11.9 แล้วเปิด Command Prompt หน้าต่างใหม่ หรือรัน `python -m venv .venv` ด้วยตำแหน่งไฟล์เต็มของ Python 3.11.9 |
| แสดงข้อความ `'nmap' is not recognized` | เปิด Command Prompt หน้าต่างใหม่หลังติดตั้ง nmap หากยังไม่ได้ ให้เพิ่มโฟลเดอร์ `C:\Program Files (x86)\Nmap` ลงในตัวแปร `PATH` ของ Windows |
| `pip install` แสดงข้อผิดพลาดเรื่องการเชื่อมต่อหรือไม่พบแพ็กเกจ | ตรวจการเชื่อมต่ออินเทอร์เน็ต หากใช้เครือข่ายองค์กรที่มีพร็อกซี ให้ตั้งค่าพร็อกซีตามที่ผู้ดูแลเครือข่ายกำหนด แล้วลองอีกครั้ง |
| แสดงข้อความ `ModuleNotFoundError: No module named 'flask'` | เรียกใช้ Python ที่ไม่ใช่ตัวในโฟลเดอร์ `.venv` ให้รันด้วย `.venv\Scripts\python.exe app.py` ตามขั้นตอนที่ 7 และตรวจว่าขั้นตอนที่ 5 จบด้วย `Successfully installed` |
| เปิด <http://127.0.0.1:5000> ในเบราว์เซอร์ไม่ได้ | แอปไม่ได้ทำงานอยู่ ตรวจว่าหน้าต่าง Command Prompt ยังเปิดอยู่และมีบรรทัด `Running on http://127.0.0.1:5000` หากไม่มี ให้เริ่มแอปตามขั้นตอนที่ 7 |
| แถบสีเหลือง "ผลการสแกนอาจไม่ครบ" ที่หน้างานสแกน | ไม่พบ nmap, ไม่ได้รันด้วยสิทธิ์ผู้ดูแลระบบ หรือไม่มี Npcap ตรวจสอบตามหัวข้อ [การติดตั้ง](#การติดตั้ง) ขั้นตอนที่ 2 และ 7 |
| สแกนไม่สำเร็จทันทีและแสดงข้อความว่าไม่พบ nmap | ปิดแอป แล้วเปิด Command Prompt หน้าต่างใหม่ด้วยสิทธิ์ผู้ดูแลระบบ ตรวจด้วย `nmap --version` แล้วเริ่มแอปใหม่ตามขั้นตอนที่ 7 |
| แอปไม่ทำงานหลังติดตั้งแพ็กเกจ | ตรวจรุ่นของ Python ด้วย `python --version` ต้องเป็น 3.11 หรือ 3.13 ไม่ใช่ 3.14 |
| พอร์ต 5000 ถูกใช้งานอยู่ | ปิดโปรแกรมอื่นที่ใช้พอร์ตนี้ หรือแก้ท้ายไฟล์ `app.py` (`app.run(...)`) เพื่อกำหนดพอร์ตอื่น |
| รายงาน PDF เป็นภาษาอังกฤษและเรียบง่ายผิดปกติ | ไม่พบ Edge หรือ Chrome ระบบจึงใช้ตัวสร้างสำรอง ติดตั้งเบราว์เซอร์ หรือกำหนด `CLYLAR_BROWSER` เป็นตำแหน่งเต็มของไฟล์ `msedge.exe` หรือ `chrome.exe` |
| ไมโครโฟนไม่ทำงาน | ต้องใช้ Chrome หรือ Edge เปิดผ่าน `http://127.0.0.1:5000` หรือ `localhost` และอนุญาตการใช้ไมโครโฟนในเบราว์เซอร์ |
| ผู้ช่วยตอบว่าปิดการใช้ AI หรือไม่มีคีย์ | ให้ผู้ดูแลระบบสูงสุดเปิดสวิตช์ **เปิดใช้งาน** ในการ์ด **ผู้ช่วย AI** และใส่คีย์ในหน้าตั้งค่า หรือเลือกใช้โมเดลในเครื่อง คำสั่งที่ระบบประมวลผลเองยังใช้ได้โดยไม่ต้องมี AI |
| ทดสอบการเชื่อมต่อโมเดลในเครื่องไม่ผ่าน | ตรวจว่า Ollama เปิดอยู่ (`ollama list` ต้องมี `scb10x/typhoon2.5-qwen3-4b`) และที่อยู่ในหน้าตั้งค่าเป็น `http://127.0.0.1:11434` |
| สแกนช่องโหว่ใช้เวลานานมาก หรือบางพอร์ตแสดงว่าค้นหา CVE ไม่สำเร็จ | ยังไม่ได้ตั้งคีย์ NVD (ระบบจึงเว้นช่วงระหว่างคำขอ) หรือ NVD ปฏิเสธคำขอชั่วคราว ตั้งคีย์ตามหัวข้อ [การตั้งค่าเพิ่มเติม](#การตั้งค่าเพิ่มเติม-ไม่บังคับ) แล้วกด **ทดสอบคีย์ที่ใช้อยู่** ในการ์ด **การค้นหา CVE (NVD)** |
| ลืมรหัสผ่านของ admin | ให้ผู้ดูแลระบบสูงสุด (superadmin) คนอื่นรีเซ็ตให้ หากไม่มีบัญชีอื่น ให้ปิดแอปก่อน แล้วลบไฟล์ `instance/scanner.db` และเริ่มแอปใหม่ ระบบจะสร้างบัญชี `admin` / `admin123` ให้อีกครั้ง (ข้อมูลทั้งหมดในแอปจะหายไป ทั้งประวัติการสแกน บัญชีผู้ใช้ และการตั้งค่า) |

---

## English

A Flask web app, branded for NT (National Telecom), that scans a network with `nmap`, looks up known vulnerabilities (CVEs) through the NVD, runs scans on a schedule, builds a PDF report, and has an AI assistant with voice commands. The interface is available in Thai (the default) and English, in a light or a dark theme.

> **Use it only on networks you own or are authorised to scan.** Scanning other people's networks without permission can be illegal.

**Contents:** [What you need](#what-you-need) · [Tested versions](#tested-versions) · [Install](#install) · [Using the app](#using-the-app) · [Optional settings](#optional-settings) · [Local AI](#local-ai-setup) · [Troubleshooting](#troubleshooting)

### What you need

This guide is written for **Windows 10 or 11** (tested on Windows 11). Linux and macOS users: see the [note at the end of the install steps](#linux-and-macos). You do not need any programming knowledge; just follow the steps one by one.

> [!IMPORTANT]
> **Use Python 3.11 or 3.13 only.** Python 3.14 does not work yet (a tester reported that the app fails on it). This guide uses **Python 3.11.9**, the version every step was tested with. If you already have 3.14 installed, install 3.11.9 alongside it and use that one in step 5.

| Program | Recommended version | What it is for | Download |
|---|---|---|---|
| Python | **3.11.9** (64-bit) | Runs the application. | [python.org/downloads/release/python-3119](https://www.python.org/downloads/release/python-3119/) |
| nmap (with Npcap) | **7.98** | Scans the network. OS detection and several scan types need administrator rights, so the app has to run as Administrator. | [nmap.org/download.html](https://nmap.org/download.html) |
| Git | 2.53 or newer | Downloads the code. Optional: a ZIP file works instead. | [git-scm.com/downloads/win](https://git-scm.com/downloads/win) |
| Microsoft Edge or Google Chrome | Latest | Opens the app's pages and prints the PDF report (Windows 10 and 11 already include Edge). | |
| Internet | | The pages load Bootstrap, icons and fonts from CDNs; CVE lookups need the NVD. | |

You need about 1 GB of disk for all of the above and the app (not counting the optional local AI and Whisper, which are separate downloads).

### Tested versions

This table is what is installed on the development machine on the day this guide was written (23 November 2026). If something breaks after you install newer versions, try the versions below.

| Item | Version |
|---|---|
| Operating system | Windows 11 Home (build 10.0.26200) |
| Python | 3.11.9 |
| nmap | 7.98 |
| Npcap | 1.83 |
| Git | 2.53.0 |
| Microsoft Edge | 158.0.4370.33 |
| Ollama (optional) | 0.40.17 |

Python packages installed on the development machine:

| Package | Version | Package | Version |
|---|---|---|---|
| Flask | 3.1.0 | APScheduler | 3.11.2 |
| Flask-Login | 0.6.3 | python-nmap | 0.7.1 |
| Flask-SQLAlchemy | 3.1.1 | requests | 2.33.1 |
| Flask-WTF | 1.3.0 | xhtml2pdf | 0.2.17 |
| Werkzeug | 3.1.3 | python-dotenv | 1.2.2 |
| psutil | 5.9.5 | websocket-client | 1.9.0 |

`requirements.txt` does not pin versions, so step 5 installs the newest release of each package, which normally works. If the app misbehaves after installing, install the versions in the table with this command instead (one command, typed on a single line; for Python 3.11.9 only, because this `psutil` release does not support Python 3.13):

```bat
.venv\Scripts\python.exe -m pip install Flask==3.1.0 Flask-Login==0.6.3 Flask-SQLAlchemy==3.1.1 Flask-WTF==1.3.0 Werkzeug==3.1.3 APScheduler==3.11.2 python-nmap==0.7.1 requests==2.33.1 xhtml2pdf==0.2.17 python-dotenv==1.2.2 psutil==5.9.5 websocket-client==1.9.0
```

This guide has not been tested on Linux, macOS or Python 3.13.

### Install

**Before you start: what is Command Prompt?** Command Prompt is the black window where you type commands. Every step in this guide uses it (not PowerShell).

- **Open it:** press the Windows key, type `cmd`, press Enter.
- **Commands:** they are in the grey boxes. Type or copy them one line at a time and press Enter after each. Wait for a command to finish (the `>` sign comes back) before typing the next line.
- **Paste text:** right-click in the window.
- **Stop a running command:** press Ctrl+C.

| Term | Meaning |
|---|---|
| `PATH` | The list of folders where Windows looks for a program when you type its name. If a program is not on the `PATH`, you get "is not recognized". |
| Virtual environment | The `.venv` folder that holds this app's own packages, apart from any other Python on the computer. |
| Administrator | The rights Windows asks you to confirm (the Yes button) before opening a program. nmap needs them to detect the OS and MAC address fully. |
| A `/24` target | `192.168.1.0/24` means the addresses 192.168.1.0 to 192.168.1.255, 256 in all. The smaller the number after `/`, the bigger the network. |
| CVE | The ID of a publicly known vulnerability, such as `CVE-2021-44228`. |

**1. Install Python 3.11.9**

1. Open <https://www.python.org/downloads/release/python-3119/>, scroll down to **Files**, and download **Windows installer (64-bit)**.
2. Open the downloaded file. At the bottom of the first window, **tick "Add python.exe to PATH" first**, then press **Install Now** (without it the `python` command will not work).
3. When it says "Setup was successful", press **Close**.
4. Open a **new** Command Prompt window and check:

```bat
python --version
```

It must show `Python 3.11.9`. If it shows something else, see [Troubleshooting](#troubleshooting).

**2. Install nmap 7.98 and Npcap**

1. Open <https://nmap.org/download.html>, find **Microsoft Windows binaries**, and download the **Latest stable release self-installer** (a file named `nmap-7.98-setup.exe`).
2. Open the file, press **I Agree**, keep every item ticked (Npcap included), and press **Install**.
3. A separate **Npcap** installer window opens during the install. Do not skip it: press **I Agree** and **Install** without changing any option, then **Finish**, until everything is installed.
4. Open a **new** Command Prompt window and check:

```bat
nmap --version
```

The first line must read `Nmap version 7.98 ( https://nmap.org )`, and the `Compiled with` line mentions `Npcap`.

**3. Install Git (skip it if you will use the ZIP file)**

1. Open <https://git-scm.com/downloads/win> and download **Git for Windows/x64 Setup**.
2. Open the file, press **Next** on every page without changing anything, then **Install** and **Finish**.
3. Open a **new** Command Prompt window and check:

```bat
git --version
```

It must show `git version 2.53.0` or newer.

**4. Download the app's code**

Command Prompt starts in your own folder (for example `C:\Users\YourName`). Type these lines one at a time:

```bat
mkdir clylar
cd clylar
git clone https://github.com/Pokerman01/CLYLAR_Network_Mapper.git
cd CLYLAR_Network_Mapper
dir
```

`dir` must list files such as `app.py` and `requirements.txt`. The app's folder is now `C:\Users\YourName\clylar\CLYLAR_Network_Mapper`.

Without Git: open the project's GitHub page, press **Code**, choose **Download ZIP**, and extract it. Then open the extracted folder in File Explorer, click the address bar at the top, type `cmd` and press Enter. That opens a Command Prompt inside the folder. Go on to step 5.

**5. Create the virtual environment and install the packages**

Type this in the same Command Prompt (which is in the `CLYLAR_Network_Mapper` folder):

```bat
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The first line takes a few seconds. The second takes 1 to 3 minutes and ends with a `Successfully installed ...` line that includes Flask. You can ignore a "A new release of pip is available" message. These commands call the Python inside `.venv` directly, so you do not need to activate the environment first.

**6. Create the settings file `.env` (recommended)**

```bat
copy .env.example .env
.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
notepad .env
```

The second command prints a long random text. Copy it (drag the mouse over the text and press Enter). The third command opens `.env` in Notepad. Add a new line at the end, with the random text pasted after `SECRET_KEY=`:

```
SECRET_KEY=the random text you copied
```

Press Ctrl+S to save and close Notepad. `SECRET_KEY` signs login sessions. The default is public in the source code, so set your own before real use or on a shared computer. For a quick trial on your own computer you can skip this step for now.

**7. Start the app as Administrator**

1. Close the old Command Prompt window.
2. Press the Windows key, type `cmd`, right-click **Command Prompt**, choose **Run as administrator**, and press **Yes** when Windows asks. The title bar must say **Administrator**.
3. Type:

```bat
cd /d "%USERPROFILE%\clylar\CLYLAR_Network_Mapper"
.venv\Scripts\python.exe app.py
```

If you downloaded the ZIP file, replace the path after `cd /d` with the folder that holds `app.py` (keep the quotation marks around it).

When it works, the window shows the lines `Running on http://127.0.0.1:5000` and `Press CTRL+C to quit` (a warning that "This is a development server" is normal). **Leave this window open**: the app runs inside it, and closing the window stops the app.

> Without administrator rights the app still opens, but OS and MAC detection are incomplete and some scan types may fail. The Tasks page shows an amber banner about it. The app only listens on the computer that runs it (`127.0.0.1`), so other computers on the network cannot reach it.

**8. First login**

1. Open Microsoft Edge or Chrome and go to <http://127.0.0.1:5000>.
2. Sign in with username **`admin`** and password **`admin123`** (the app creates this superadmin account and the database `instance/scanner.db` by itself on the first start).
3. **Change the password at once.** Click the letter circle at the top right, choose **User Management**, find the `admin` row and press **Reset Password**. The default password is only for trying the app out.

**9. Check that it works**

Try scanning your own computer, which is safe and quick.

1. Choose **Tasks** in the left menu and press the **New Scan** button.
2. Name the job, for example `test`, enter the target `127.0.0.1`, choose **Fast Scan**, and press **Scan**.
3. Within a few seconds the status must change to finished. Press the **View** button in the job's row to open the scan's result page; it must show 1 device (your own computer).

If the scan fails or an amber banner appears, see [Troubleshooting](#troubleshooting).

**Next time you want to use it** you do not need to install again. Open Command Prompt as administrator (as in step 7) and type the same two lines:

```bat
cd /d "%USERPROFILE%\clylar\CLYLAR_Network_Mapper"
.venv\Scripts\python.exe app.py
```

Press Ctrl+C in that window to stop the app. All data is kept in the `instance` folder and survives closing the app.

**Updating to a newer version.** Stop the app first (Ctrl+C), then type in the app's folder:

```bat
git pull
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

#### Linux and macOS

These steps are **not tested**. You need Python 3.11, nmap and Git.

```bash
sudo apt install python3 python3-venv git nmap      # Debian / Ubuntu
brew install python@3.11 nmap git                   # macOS (Homebrew)
git clone https://github.com/Pokerman01/CLYLAR_Network_Mapper.git
cd CLYLAR_Network_Mapper
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
sudo .venv/bin/python app.py
```

Then open <http://127.0.0.1:5000>. The PDF report needs Google Chrome or Microsoft Edge on the computer.

### Using the app

#### Your first scan

1. Sign in and choose **Tasks** (งานสแกน) in the left menu.
2. Press the **New Scan** button. Give it a name, enter a **target** such as `192.168.1.0/24` (a whole network) or `192.168.1.10` (one device), and choose a scan type.
3. Start it. The scan is queued and runs in the background, so you can move to another page while you wait. A notice appears at the bottom right when it finishes.
4. On the Tasks page, press the arrow in a job's row to see its details: the exact nmap command, progress and a summary. The stop button cancels a waiting or running job (it really stops nmap).
5. When it has finished, press the **View** button in the job's row to open the scan's result page.

Two scans run at the same time; the rest wait in the queue. A scan that runs past its time limit stops by itself and is marked failed (by default Discovery 1 hour, Fast Scan 2 hours, Intense, Vulnerability and Custom 4 hours; the all-ports, Gentle and UDP options raise the limit to 6 to 8 hours).

#### Scan types

| Type | Use it when |
|---|---|
| Discovery | You want to know which devices are online. No port scan; the fastest. It also reads device names from mDNS / SSDP. |
| Fast Scan | You want the 100 most common ports, with service versions and the OS. |
| Intense Scan | You want a thorough look at the 1,000 most common ports, with OS and traceroute. Slower. |
| Vulnerability Scan (CVE) | You want an Intense Scan followed by a CVE search at the NVD, using the product name and version found on each open port. |
| Custom Scan | You want to choose nmap options yourself, from the list the app allows (no `--script`, no output files). |
| XML Upload | You want to look at an nmap `-oX` result that was made elsewhere. |

The **Advanced options** of the new-scan box offer Timing, no ping (`-Pn`), scan all ports (1-65535), no DNS, find devices that ignore ping, Gentle mode and common UDP ports. Turn on the **Show command** switch at the top right of the box to see the exact nmap command the app will run.

> **About CVE results:** the lookup is a keyword search on the product and version of a service, not CPE matching, and keeps at most 5 CVEs per service. Some results may not fit the real device, so check them before you rely on them. A service that could not be looked up is shown as "unknown", never as "none found".

#### Reading the results

| Menu | What it gives you |
|---|---|
| Dashboard | An overview: devices, open ports, CVEs, job status and what changed since the previous scan. Each section can be shown or hidden with the button next to the date. |
| History | Every scan. Search by IP, target or name, or use the advanced filter (for example port 445 and an OS containing "windows" on the same device). |
| Devices | Every device found. Click an IP to open the device page: its ports, CVEs and history across all scans. |
| Vulnerabilities | The CVEs found, filtered by severity, with a coverage overview and the affected devices. |
| Network Topology | A network diagram combined from several scans. Drag to move, and choose the grouping (/24, /16 or None) with the cog at the top right of the diagram. Search and filter devices from the left panel. |
| Reports | Download a PDF summary (A4 portrait or landscape) or export CSV. The PDF needs Edge or Chrome on the computer. |

#### Re-scans and schedules

- **Rescan:** on the Tasks page, press the rescan button of a finished job; the box opens with the original settings.
- **Drill-down:** on a scan report, click a device to scan just that device in more depth.
- **Schedule:** in the new-scan box, open the schedule section to repeat a scan on a timetable. You can type the time directly, for example `14:30` or `2pm`. Schedules run only while the app is running.

#### Assistant and voice commands

- The **Assistant** page is a chat. Type a command such as "scan 192.168.1.10", or ask "how many devices" or "open the reports page". The system handles scan commands, questions about your data and opening pages by itself, without AI. Other questions go to the AI (needs setup, see [Optional settings](#optional-settings)).
- Every scan command needs your confirmation (**Confirm, scan now**) on a card before it starts, unless you turn on the **Scan right away** switch (only for private networks of /24 or smaller). The AI can never start a scan by itself: even when it proposes a scan in the chat window opened from the floating button, you must confirm it on the card.
- The floating button at the bottom right opens the chat, starts a voice command or a quick scan. The **Voice** page is a full-page voice screen. Voice needs Chrome or Edge, opened through `localhost` or HTTPS.
- While the AI is writing an answer you can go to another page; the answer waits for you, and there are Stop and Retry buttons.

#### User roles

| Role | Can do |
|---|---|
| Superadmin | Manages every user, sets the shared AI key, chooses the AI model and switches the AI on or off. |
| Admin | Runs scans and schedules, uses the Assistant, and creates user accounts of their own. Sees only the scans they started. |
| User | Views the scans of the admin who created the account. Cannot start scans and has no Assistant. |

#### Language, theme and personal settings

The light / dark theme button and the Thai / English switch are in the top bar. Your choice is saved with your account. The PDF report is always Thai and light.

### Optional settings

- **Online AI assistant (Gemini).** Put a key in a `.env` file (copy `.env.example`), or paste it on the Settings page (a superadmin sets the shared key, any admin can set their own). Settings-page keys take priority over `.env`. Get a key at <https://aistudio.google.com/app/apikey>. A superadmin chooses the Gemini model from a list on the Settings page; the list shows the models the shared key can use, so set the key first. When you switch from the local model to Gemini, the app warns you first that questions will be sent to Google. The AI sees every total but only part of the device, vulnerability and scan lists; to get details about one item, include its IP address or CVE ID in your question. Without a key, voice commands and the Assistant page still handle what the system understands itself (scans, counts, opening pages).
- **NVD key (CVE lookup).** Used by the Vulnerability Scan. Optional: without a key the lookup still works but is slower, because NVD allows only 5 requests per 30 seconds (so the system waits about 6.5 seconds between requests). Request a free key at <https://nvd.nist.gov/developers/request-an-api-key>. NVD emails the key, and you must click the confirmation link in that email before it works. Then put the key after `NVD_API_KEY=` in the `.env` file, or enter it on the **Settings** page in the **CVE lookup (NVD)** card (superadmin only). A key set on the Settings page takes priority over the `.env` file.
- **Local AI (Ollama + Typhoon).** Answers questions with a model that runs on your own computer instead of Gemini, so nothing leaves it. Full setup guide: [Local AI setup](#local-ai-setup).
- **Local voice engine (Whisper).** Turns spoken commands into text on your own computer instead of sending audio to the browser vendor. It is a separate download of about 3 GB and needs its own setup: see **[docs/whisper-setup.md](docs/whisper-setup.md)**. Without it the app uses the browser's engine.
- **Other environment variables.** `CLYLAR_BROWSER` (full path of Edge or Chrome if the app cannot find it), `CLYLAR_SCAN_TIME_LIMIT` (scan time limit in seconds, replacing every default; `0` turns the limit off), `MAC_LOOKUP_ONLINE=1` (look up a MAC's maker online when nmap's list has no match; this sends the first half of the MAC to a third party).

### Local AI setup

The assistant can answer questions with the **Typhoon 2.5 (Qwen3 4B)** model running on your own computer through [Ollama](https://ollama.com), instead of Gemini. The summary figures attached to a question never leave the computer that runs the app, and no API key is needed. This setup is optional.

| | |
|---|---|
| Operating system | Windows, macOS or Linux, as supported by Ollama. |
| Disk | About 2.5 GB for the model, plus about 3 GB for the Ollama program on Windows. |
| Memory | About 4 to 4.5 GB while the model runs (RAM and graphics memory together). |
| Graphics card (GPU) | Optional. An NVIDIA card makes answers faster; without one the CPU is used, which is slower. |
| Internet | Only to download Ollama and the model. After that it works offline. |

**Steps**

1. **Install Ollama** (tested version 0.40.17). Download the Windows installer from <https://ollama.com/download>, open it and press **Install**. The installer starts Ollama in the background (an icon appears at the right end of the taskbar) at `http://127.0.0.1:11434`. Open a new Command Prompt window and check it with:

   ```bash
   ollama --version
   ```

2. **Download the model.** It takes several minutes, depending on your internet speed.

   ```bash
   ollama pull scb10x/typhoon2.5-qwen3-4b
   ```

   Check that it is listed:

   ```bash
   ollama list
   ```

   If it says `could not connect to a running Ollama instance`, Ollama is not running: open the **Ollama** app from the Start menu and try the command again.

3. **Choose it in the app.** Sign in as a superadmin (only a superadmin can change this). Open **Settings**, and in the **AI assistant** card choose **Local (Typhoon)** under **Answered by**.
4. **Test it.** Press **Test connection**. The app reports whether Ollama answers and whether the configured model is installed. The test does not call the model and does not load it into memory.
5. **Use it.** Ask the Assistant as usual, on the **Assistant** page or with the floating button. Answers carry the **AI (local model)** badge, and the tooltip of the status line (hover over it) says the question stays on this computer. If an answer is slow, press **Stop**: the model stops writing at once.

**Settings.** Press **Set up model** in the same card.

| Field | Meaning |
|---|---|
| Ollama server address | Default `http://127.0.0.1:11434`. It must be the computer that runs the app (`127.0.0.1` or `localhost`); the address of another machine is refused. |
| Model name | Default `scb10x/typhoon2.5-qwen3-4b`. Installed models are offered in a list. You can try another model, but the project only tested Typhoon. |
| Layers on the GPU | Default 20. Leave it empty to let Ollama decide. Lower it if the graphics card runs out of memory, especially while Whisper is also running (using both at once has not been tested). |

**Good to know**

- **It never falls back to Gemini by itself.** If the local model fails, the app shows an error and says the question was not sent to Gemini. To use Gemini, change **Answered by** back.
- **The main AI switch** in the same card still turns the assistant's AI off for both engines. Commands the system handles itself (starting a scan, counts, opening pages) always work without any AI.
- **Speech to text does not change.** It still uses Whisper or the browser's engine. This model only answers text.
- **Speed.** The first question is slow because the model has to load. On a laptop with an RTX 3060 (6 GB) that was about 85 seconds, then about 5 to 13 seconds per answer; your computer may differ. Ollama unloads the model after about 5 idle minutes, so the next question is slow again. The app waits up to 4 minutes for an answer.
- **One question at a time.** Questions sent to the local model queue up and are answered in turn.
- **Usage.** The usage table on the Settings page counts questions answered by the local model on their own line, and does not count them as Gemini tokens.

**Removing it.** To free about 2.5 GB, run `ollama rm scb10x/typhoon2.5-qwen3-4b`. To keep models on another drive, set `OLLAMA_MODELS` as described in Ollama's documentation.

| What you see | What to do |
|---|---|
| The connection test fails | Ollama is not running, or has only just started. After the computer starts it can take 1 to 2 minutes (the Settings page retries by itself for about 2 minutes). If it still fails, start the Ollama app (or run `ollama serve`), check the Ollama server address, and press **How to fix it** next to the message for step-by-step help. |
| It says the model was not found | The model has not been downloaded, or the name in the field does not match `ollama list`. |
| Answers are very slow | Run `ollama ps` to see whether the graphics card carries part of the model. CPU only is slow. Try more layers on the GPU if graphics memory allows. |
| Out of memory | Lower the layers on the GPU, or turn Whisper off for a while. |
| The address will not save | It must be the computer that runs the app (`127.0.0.1` or `localhost`). Another machine's address is refused. |

### Troubleshooting

| What you see | What to do |
|---|---|
| `'python' is not recognized`, or the Microsoft Store opens | "Add python.exe to PATH" was not ticked during install. Uninstall Python (Settings > Apps) and install it again with that box ticked, or go to Settings > Apps > Advanced app settings > App execution aliases and turn off `python.exe`. |
| `python --version` is not 3.11.9 | Several Python versions are installed. Install 3.11.9 and make sure you opened a new Command Prompt, or run `python -m venv .venv` with the full path of Python 3.11.9. |
| `'nmap' is not recognized` | Open a new Command Prompt window after installing nmap. If it still fails, add the folder `C:\Program Files (x86)\Nmap` to the Windows `PATH`. |
| `pip install` fails with a connection error or "no matching distribution" | Check the internet. On a company network with a proxy, set up the proxy as your network administrator describes, then try again. |
| `ModuleNotFoundError: No module named 'flask'` | The wrong Python was used. Run `.venv\Scripts\python.exe app.py` as in step 7, and check that step 5 ended with `Successfully installed`. |
| <http://127.0.0.1:5000> does not open in the browser | The app is not running. Check that the Command Prompt window is still open and shows `Running on http://127.0.0.1:5000`. If not, start the app as in step 7. |
| An amber banner "scan results may be incomplete" on the Tasks page | nmap is missing, the app is not running as administrator, or Npcap is missing. See steps 2 and 7 of [Install](#install). |
| Scans fail at once and say nmap is not found | Open a new terminal after installing nmap and check `nmap --version`. |
| The app does not run after installing the packages | Check `python --version`: it must be 3.11 or 3.13, not 3.14. |
| Port 5000 is in use | Close the other program that uses it, or edit the last lines of `app.py` (`app.run(...)`) to choose another port. |
| The PDF report looks plain and in English | Edge or Chrome was not found, so the fallback builder was used. Install one, or set `CLYLAR_BROWSER` to the path of `msedge.exe` or `chrome.exe`. |
| The microphone does not work | Use Chrome or Edge, open the app at `http://127.0.0.1:5000` or `localhost`, and allow the microphone in the browser. |
| The Assistant says the AI is off or has no key | A superadmin turns the AI switch on and enters a key on the Settings page, or chooses the local model. Commands the system understands itself work without any AI. |
| The local model's connection test fails | Check that Ollama is running (`ollama list` should show `scb10x/typhoon2.5-qwen3-4b`) and that the address on the Settings page is `http://127.0.0.1:11434`. |
| A Vulnerability Scan is very slow, or some ports say the CVE lookup failed | No NVD key is set (so the system waits between requests), or NVD refused a request for a moment. Set a key as described in [Optional settings](#optional-settings), then press **Test the key in use** in the **CVE lookup (NVD)** card. |
| You forgot the admin password | Ask another superadmin to reset it. If there is no other account, stop the app, delete `instance/scanner.db` and start the app again; it creates the `admin` / `admin123` account again (everything in the app is lost: scan history, user accounts and settings). |
