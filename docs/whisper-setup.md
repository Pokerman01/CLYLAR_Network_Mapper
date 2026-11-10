# Setting up local Whisper / การติดตั้ง Whisper ในเครื่อง

## ภาษาไทย

CLYLAR ถอดเสียงคำสั่งพูดเป็นข้อความได้ด้วย **โมเดล Whisper ที่ทำงานในเครื่อง** ซึ่งเป็นตัวเลือกเสริม หากไม่ติดตั้ง ไมโครโฟนในแชทจะใช้ตัวถอดเสียงของเบราว์เซอร์ ซึ่งส่งเสียงไปยัง Google (Chrome) หรือ Microsoft (Edge) และถอดที่อยู่ IP ได้แม่นยำน้อยกว่า

โมเดล **ไม่ได้อยู่ในที่เก็บโค้ดนี้** เพราะมีขนาดประมาณ 3 GB และ GitHub ไม่รับไฟล์เดี่ยวที่ใหญ่กว่า 100 MB ให้ดาวน์โหลดครั้งเดียวจากแหล่งเผยแพร่บน Hugging Face ลงในโฟลเดอร์ที่อยู่ข้างเดสก์ท็อปของคุณ ไม่ต้องใช้สำเนาบน Google Drive

### สิ่งที่ต้องมี

| | |
|---|---|
| Windows | ขั้นตอนด้านล่างเขียนสำหรับ Windows (ตัวแอปและ `start_whisper_worker.bat` เขียนไว้สำหรับระบบนี้) |
| Python 3.11 | ใช้สภาพแวดล้อมเสมือน (virtual environment) แยกสำหรับ Whisper จึงไม่กระทบแพ็กเกจของตัวแอป |
| พื้นที่ดิสก์ | ประมาณ 5.5 GB: โมเดล 3.1 GB และสภาพแวดล้อมเสมือน 2.3 GB |
| การ์ดจอ NVIDIA (แนะนำ) | ใช้เวลาประมาณ 1 ถึง 2 วินาทีต่อคำสั่ง หากไม่มี Whisper จะทำงานบน CPU แทน ใช้งานได้แต่ใช้เวลาประมาณ 8 ถึง 17 วินาทีต่อคำสั่ง |
| อินเทอร์เน็ต | ใช้เฉพาะตอนดาวน์โหลดครั้งแรก |

### ขั้นตอน

เปิด **Command Prompt** (ไม่ใช่ PowerShell) แล้วสั่งทีละบรรทัด

**1. สร้างโฟลเดอร์** ค่าเริ่มต้นคือโฟลเดอร์ `clylar-whisper-lab` บนเดสก์ท็อป

```bat
mkdir "%USERPROFILE%\Desktop\clylar-whisper-lab"
cd /d "%USERPROFILE%\Desktop\clylar-whisper-lab"
```

**2. สร้างสภาพแวดล้อมเสมือนและติดตั้งแพ็กเกจ** เวอร์ชันด้านล่างคือเวอร์ชันที่ใช้พัฒนาและทดสอบ

```bat
python -m venv venv
venv\Scripts\python.exe -m pip install --upgrade pip
venv\Scripts\python.exe -m pip install faster-whisper==1.2.1 nvidia-cublas-cu12 nvidia-cudnn-cu12
```

แพ็กเกจที่ขึ้นต้นด้วย `nvidia-` คือไลบรารี CUDA สำหรับการ์ดจอ หากไม่มีการ์ดจอ NVIDIA ให้ข้ามสองแพ็กเกจนี้ได้ (Whisper จะทำงานบน CPU)

**3. ดาวน์โหลดโมเดล** คำสั่งนี้ระบุเวอร์ชันที่ตรงกับที่ทดสอบไว้

```bat
venv\Scripts\python.exe -c "from huggingface_hub import snapshot_download; snapshot_download('Avocaduu14/whisper-th-large-v3-ct2', revision='1a1554ea606d89c937216ada609bb8585e20a36e', local_dir='models/thai-large')"
```

ใช้เวลาไม่กี่นาที เมื่อเสร็จแล้ว โฟลเดอร์ `models\thai-large` ต้องมีไฟล์ `model.bin` (ประมาณ 3 GB), `config.json`, `tokenizer.json`, `vocabulary.json` และ `preprocessor_config.json`

ชื่อโฟลเดอร์ต้องเป็น `thai-large` ตามนี้ทุกตัวอักษร เพราะแอปค้นหาไฟล์ `models\thai-large\model.bin`

**4. เริ่มทำงาน** เลือกวิธีใดวิธีหนึ่ง

- เปิดแอป ไปที่หน้า **ตั้งค่า** แล้วเปิดสวิตช์ในการ์ด **ตัวถอดเสียงพูด (Whisper ในเครื่อง)**
- หรือดับเบิลคลิก `start_whisper_worker.bat` ในโฟลเดอร์โปรเจกต์ แล้วเปิดหน้าต่างนั้นทิ้งไว้

การเริ่มครั้งแรกต้องโหลดโมเดล ใช้เวลา 10 ถึง 20 วินาที จากนั้นการ์ดจะแสดง **พร้อมใช้งาน** พร้อมระบุว่าใช้การ์ดจอ (**ใช้การ์ดจอ**) หรือ CPU (**ใช้ CPU (ช้า)**)

Whisper ไม่เริ่มทำงานเองเมื่อเปิดเครื่องใหม่ กรุณาเปิดสวิตช์อีกครั้ง

### หากโฟลเดอร์อยู่ที่อื่น

กำหนดค่า `CLYLAR_WHISPER_HOME` เป็นโฟลเดอร์ที่มี `venv` และ `models` ก่อนเริ่มแอปและก่อนรัน `start_whisper_worker.bat`

```bat
setx CLYLAR_WHISPER_HOME "D:\tools\clylar-whisper-lab"
```

หลังสั่งแล้ว ให้เปิดหน้าต่างใหม่เพื่อให้ค่ามีผล

### ปัญหาที่พบบ่อย

| สิ่งที่เห็น | ความหมาย |
|---|---|
| การ์ดแสดง **ยังไม่ได้ติดตั้ง Whisper ในเครื่องนี้** | แอปไม่พบ `venv\Scripts\python.exe` หรือ `models\thai-large\model.bin` ในโฟลเดอร์ข้างต้น กรุณาตรวจชื่อโฟลเดอร์และโครงสร้างตามขั้นตอนที่ 3 |
| การ์ดแสดง **ใช้ CPU (ช้า)** และไฟล์บันทึกระบุว่าไม่พบ `cublas64_12.dll` | สภาพแวดล้อมยังไม่มีแพ็กเกจ CUDA กรุณารันคำสั่ง `pip install` ในขั้นตอนที่ 2 อีกครั้งโดยรวมแพ็กเกจ `nvidia-` |
| การ์ดแสดงข้อผิดพลาดหลังกดสวิตช์ | อ่านบรรทัดท้ายของไฟล์ `instance\whisper_worker.log` ในโฟลเดอร์โปรเจกต์ หากพอร์ตถูกใช้อยู่ แสดงว่ามีอีกสำเนาหนึ่งทำงานอยู่ (พอร์ต 5057) |
| หน้าต่างแสดงบรรทัดเช่น `forrtl: error (200) ... window-CLOSE event` | เป็นเรื่องปกติ ข้อความนี้แสดงเมื่อปิดหน้าต่าง Whisper ไม่ใช่ข้อผิดพลาด |
| คำสั่งเสียงใช้ได้แต่ช้า | Whisper ทำงานบน CPU ดูแถวที่สองของตารางนี้ |

หากต้องการหยุด Whisper ให้ปิดสวิตช์ในหน้าตั้งค่า หรือปิดหน้าต่าง `start_whisper_worker.bat` จากนั้นไมโครโฟนในแชทจะกลับไปใช้ตัวถอดเสียงของเบราว์เซอร์เอง

### เกี่ยวกับโมเดล

- **แหล่งดาวน์โหลด:** <https://huggingface.co/Avocaduu14/whisper-th-large-v3-ct2> (คำสั่งในขั้นตอนที่ 3 ดาวน์โหลดจากที่นี่ หรือจะดาวน์โหลดไฟล์เองจากแท็บ "Files" ของหน้านั้นลงในโฟลเดอร์ `models\thai-large` ก็ได้)
- **ชื่อ:** `Avocaduu14/whisper-th-large-v3-ct2` บน Hugging Face เป็นโมเดลที่แปลงเป็นรูปแบบ CTranslate2 จาก Whisper large-v3 ที่ปรับให้เหมาะกับภาษาไทย กรุณาอ่านเอกสารประกอบโมเดล (model card) เพื่อดูใบอนุญาตและการให้เครดิตก่อนนำไปเผยแพร่ต่อ (ขณะที่โครงการนี้เลือกใช้ โมเดลนี้เผยแพร่ภายใต้ Apache-2.0)
- **เหตุผลที่ใช้โมเดลปรับสำหรับภาษาไทย:** จากเสียงที่บันทึกไว้ของโครงการนี้ โมเดลนี้เข้าใจคำสั่งสแกนที่พูดได้ดีกว่าตัวถอดเสียงของเบราว์เซอร์มาก (8 จาก 10 เทียบกับ 1 หรือ 2 จาก 10)
- **ความเป็นส่วนตัว:** เสียงไม่ออกจากเครื่องและไม่มีการจัดเก็บ โปรแกรมรับคำขอที่ `127.0.0.1` เท่านั้น
- **ยังไม่ได้ทดสอบ:** คู่มือนี้อ้างอิงการตั้งค่าบนเครื่องพัฒนา ยังไม่ได้ทดสอบการติดตั้งใหม่ทั้งหมดตามขั้นตอนนี้เพียงอย่างเดียว

---

## English

CLYLAR can turn spoken commands into text with a **local Whisper model**. It is optional. Without it the chat microphone uses the browser's own speech engine, which sends the audio to Google (Chrome) or Microsoft (Edge) and reads IP addresses less reliably.

The model is **not in this repository**: it is about 3 GB, and GitHub refuses single files over 100 MB. You download it once, from its public home on Hugging Face, into a folder next to your Desktop. Nothing here needs a Google Drive copy.

### What you need

| | |
|---|---|
| Windows | The steps below are for Windows (the app and `start_whisper_worker.bat` are written for it). |
| Python 3.11 | A separate virtual environment is used for Whisper, so it does not touch the app's Python packages. |
| Disk | About 5.5 GB: the model 3.1 GB and the environment 2.3 GB. |
| NVIDIA graphics card (recommended) | About 1 to 2 seconds per spoken command. Without one Whisper falls back to the CPU: it works, but takes about 8 to 17 seconds per command. |
| Internet | Only for the one-time download. |

### Steps

Open **Command Prompt** (not PowerShell) and run these one at a time.

**1. Make the folder.** The app looks for `clylar-whisper-lab` on your Desktop by default.

```bat
mkdir "%USERPROFILE%\Desktop\clylar-whisper-lab"
cd /d "%USERPROFILE%\Desktop\clylar-whisper-lab"
```

**2. Make the environment and install the packages.** These are the versions the feature was built and tested with.

```bat
python -m venv venv
venv\Scripts\python.exe -m pip install --upgrade pip
venv\Scripts\python.exe -m pip install faster-whisper==1.2.1 nvidia-cublas-cu12 nvidia-cudnn-cu12
```

The two `nvidia-` packages are the CUDA libraries for the graphics card. Skip them only if you have no NVIDIA card (Whisper then runs on the CPU).

**3. Download the model.** It is pinned to the exact revision the project was tested with.

```bat
venv\Scripts\python.exe -c "from huggingface_hub import snapshot_download; snapshot_download('Avocaduu14/whisper-th-large-v3-ct2', revision='1a1554ea606d89c937216ada609bb8585e20a36e', local_dir='models/thai-large')"
```

It takes a few minutes. When it finishes, `models\thai-large` must hold `model.bin` (about 3 GB), `config.json`, `tokenizer.json`, `vocabulary.json` and `preprocessor_config.json`.

The folder must be named exactly `thai-large`: the app looks for `models\thai-large\model.bin`.

**4. Start it.** Either:

- open the app, go to **Settings**, and turn on the switch in the card **ตัวถอดเสียงพูด (Whisper ในเครื่อง)**; or
- double-click `start_whisper_worker.bat` in the project folder and leave its window open.

The first start loads the model and takes 10 to 20 seconds. The card then says **พร้อมใช้งาน** and shows whether it uses the graphics card (**ใช้การ์ดจอ**) or the CPU (**ใช้ CPU (ช้า)**).

Whisper does not start by itself when the computer restarts: turn the switch on again.

### If the folder is somewhere else

Set `CLYLAR_WHISPER_HOME` to the folder that holds `venv` and `models`, before starting the app and before running `start_whisper_worker.bat`:

```bat
setx CLYLAR_WHISPER_HOME "D:\tools\clylar-whisper-lab"
```

Open a new window afterwards so the setting is read.

### Problems

| What you see | What it means |
|---|---|
| The card says **ยังไม่ได้ติดตั้ง Whisper ในเครื่องนี้** | The app cannot find `venv\Scripts\python.exe` or `models\thai-large\model.bin` in the folder above. Check the folder name and the layout in step 3. |
| The card says **ใช้ CPU (ช้า)** and the log says `cublas64_12.dll` was not found | The CUDA packages are missing from the environment. Run the `pip install` of step 2 again, with the `nvidia-` packages. |
| The card shows an error after you pressed the switch | Read the last lines of `instance\whisper_worker.log` in the project folder. A port already in use means another copy is running (port 5057). |
| A window with lines like `forrtl: error (200) ... window-CLOSE event` | Normal. It is printed when the Whisper window is closed. It is not an error. |
| Voice commands work but are slow | It is running on the CPU. See the second row of the table above. |

To stop Whisper, turn the switch off in Settings or close the `start_whisper_worker.bat` window. The chat microphone then goes back to the browser's engine by itself.

### About the model

- **Where to get it:** <https://huggingface.co/Avocaduu14/whisper-th-large-v3-ct2> (the command in step 3 downloads it from there; you can also download the files by hand from that page's "Files" tab into `models\thai-large`).
- **Name:** `Avocaduu14/whisper-th-large-v3-ct2` on Hugging Face, a CTranslate2 conversion of a Thai-tuned Whisper large-v3. Read its model card for the licence and credits before you redistribute it (it was Apache-2.0 when this project adopted it).
- **Why a Thai-tuned model:** on this project's own recordings it understood spoken scan commands far better than the browser's engine (8 of 10 against 1 or 2 of 10).
- **Privacy:** the audio never leaves the computer and nothing is stored. The program listens on `127.0.0.1` only.
- **Not tested here:** this guide follows the setup of the development machine. A completely clean install following only these steps has not been repeated.
