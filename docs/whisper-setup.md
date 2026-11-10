# Setting up local Whisper / การติดตั้ง Whisper ในเครื่อง

## ภาษาไทย

CLYLAR สามารถถอดเสียงคำสั่งเป็นข้อความด้วย **โมเดล Whisper ที่ทำงานในเครื่อง** การติดตั้งนี้ไม่บังคับ หากไม่ติดตั้ง ไมโครโฟนในแชทจะใช้ตัวถอดเสียงของเบราว์เซอร์แทน ซึ่งจะส่งเสียงไปยัง Google (Chrome) หรือ Microsoft (Edge) และถอดที่อยู่ IP ได้แม่นยำน้อยกว่า

ที่เก็บโค้ดนี้ **ไม่มีไฟล์โมเดล** เนื่องจากโมเดลมีขนาดประมาณ 3 GB และ GitHub ไม่รับไฟล์ที่ใหญ่กว่า 100 MB จึงต้องดาวน์โหลดโมเดลจาก Hugging Face ซึ่งเป็นแหล่งเผยแพร่ทางการ โดยดาวน์โหลดเพียงครั้งเดียวลงในโฟลเดอร์บนเดสก์ท็อป ไม่ต้องใช้ไฟล์จาก Google Drive

### สิ่งที่ต้องมี

> [!IMPORTANT]
> **ใช้ Python 3.11 หรือ 3.13 เท่านั้น** Python 3.14 ยังใช้งานไม่ได้ (ผู้ทดสอบรายงานว่าทั้งโครงการไม่ทำงาน) หากติดตั้ง Python 3.14 ไว้ กรุณาติดตั้งรุ่น 3.13 เพิ่ม และใช้รุ่นนั้นสร้างสภาพแวดล้อมเสมือน

| | |
|---|---|
| Windows | ขั้นตอนในคู่มือนี้ใช้กับ Windows เนื่องจากตัวแอปและ `start_whisper_worker.bat` เขียนขึ้นสำหรับ Windows |
| **Python 3.11 หรือ 3.13** | Whisper ใช้สภาพแวดล้อมเสมือน (virtual environment) ของตนเอง จึงไม่กระทบแพ็กเกจ Python ของตัวแอป ไม่รองรับ 3.14 (ดูหมายเหตุด้านบน) |
| พื้นที่ดิสก์ | ประมาณ 5.5 GB แบ่งเป็นโมเดล 3.1 GB และสภาพแวดล้อมเสมือน 2.3 GB |
| การ์ดจอ NVIDIA (แนะนำ) | ถอดเสียงได้ในประมาณ 1 ถึง 2 วินาทีต่อคำสั่ง หากไม่มีการ์ดจอ NVIDIA ระบบจะใช้ CPU แทน ซึ่งใช้งานได้แต่ใช้เวลาประมาณ 8 ถึง 17 วินาทีต่อคำสั่ง |
| อินเทอร์เน็ต | ใช้เฉพาะตอนดาวน์โหลดครั้งแรก |

### ขั้นตอนการติดตั้ง

เปิด **Command Prompt** (ไม่ใช่ PowerShell) แล้วรันคำสั่งทีละบรรทัด

**1. สร้างโฟลเดอร์** โดยค่าเริ่มต้น แอปจะค้นหาโฟลเดอร์ `clylar-whisper-lab` บนเดสก์ท็อป

```bat
mkdir "%USERPROFILE%\Desktop\clylar-whisper-lab"
cd /d "%USERPROFILE%\Desktop\clylar-whisper-lab"
```

**2. สร้างสภาพแวดล้อมเสมือนและติดตั้งแพ็กเกจ** เวอร์ชันที่ระบุด้านล่างเป็นเวอร์ชันที่ใช้พัฒนาและทดสอบฟีเจอร์นี้

```bat
python -m venv venv
venv\Scripts\python.exe -m pip install --upgrade pip
venv\Scripts\python.exe -m pip install faster-whisper==1.2.1 av==18.1.0 nvidia-cublas-cu12 nvidia-cudnn-cu12
```

แพ็กเกจ 2 รายการที่ขึ้นต้นด้วย `nvidia-` คือไลบรารี CUDA สำหรับการ์ดจอ ให้ข้ามแพ็กเกจทั้งสองเฉพาะเมื่อเครื่องไม่มีการ์ดจอ NVIDIA ในกรณีนั้น Whisper จะทำงานบน CPU

ต้องระบุ `av==18.1.0` ไว้ด้วย เนื่องจาก PyAV รุ่น 19 ขึ้นไปใช้งานร่วมกับ faster-whisper 1.2.1 ไม่ได้ ทำให้การถอดเสียงทุกครั้งไม่สำเร็จและแสดง `cannot_transcribe`

**3. ดาวน์โหลดโมเดล** คำสั่งนี้ระบุรุ่น (revision) ของโมเดลให้ตรงกับรุ่นที่โครงการทดสอบไว้

```bat
venv\Scripts\python.exe -c "from huggingface_hub import snapshot_download; snapshot_download('Avocaduu14/whisper-th-large-v3-ct2', revision='1a1554ea606d89c937216ada609bb8585e20a36e', local_dir='models/thai-large')"
```

การดาวน์โหลดใช้เวลาหลายนาที ขึ้นอยู่กับความเร็วอินเทอร์เน็ต เมื่อเสร็จแล้ว โฟลเดอร์ `models\thai-large` ต้องมีไฟล์ `model.bin` (ประมาณ 3 GB), `config.json`, `tokenizer.json`, `vocabulary.json` และ `preprocessor_config.json`

ชื่อโฟลเดอร์ต้องเป็น `thai-large` ตรงตามนี้ทุกตัวอักษร เนื่องจากแอปจะค้นหาไฟล์ `models\thai-large\model.bin`

**4. เริ่มการทำงาน** ทำได้ 2 วิธี

- เปิดแอป ไปที่หน้า **ตั้งค่า** แล้วเปิดสวิตช์ในการ์ด **ตัวถอดเสียงพูด (Whisper ในเครื่อง)**
- ดับเบิลคลิกไฟล์ `start_whisper_worker.bat` ในโฟลเดอร์โปรเจกต์ และเปิดหน้าต่างที่ขึ้นมาค้างไว้

การเริ่มครั้งแรกต้องโหลดโมเดล ซึ่งใช้เวลา 10 ถึง 20 วินาที จากนั้นการ์ดจะแสดงสถานะ **พร้อมใช้งาน** และบอกว่าใช้การ์ดจอ (**ใช้การ์ดจอ**) หรือใช้ CPU (**ใช้ CPU (ช้า)**)

Whisper จะไม่เริ่มทำงานเองหลังรีสตาร์ตเครื่อง กรุณาเปิดสวิตช์อีกครั้งทุกครั้งที่เปิดเครื่องใหม่

### กรณีเก็บโฟลเดอร์ไว้ที่อื่น

ให้กำหนดตัวแปร `CLYLAR_WHISPER_HOME` เป็นโฟลเดอร์ที่มี `venv` และ `models` อยู่ข้างใน โดยต้องกำหนดก่อนเริ่มแอปและก่อนรัน `start_whisper_worker.bat`

```bat
setx CLYLAR_WHISPER_HOME "D:\tools\clylar-whisper-lab"
```

ค่านี้จะมีผลในหน้าต่างที่เปิดใหม่หลังจากรันคำสั่งเท่านั้น

### ปัญหาที่พบบ่อย

| อาการ | สาเหตุและวิธีแก้ |
|---|---|
| การ์ดแสดงข้อความ **ยังไม่ได้ติดตั้ง Whisper ในเครื่องนี้** | แอปไม่พบ `venv\Scripts\python.exe` หรือ `models\thai-large\model.bin` ในโฟลเดอร์ดังกล่าว กรุณาตรวจสอบชื่อโฟลเดอร์และโครงสร้างโฟลเดอร์ตามขั้นตอนที่ 2 และ 3 |
| การ์ดแสดง **ใช้ CPU (ช้า)** และไฟล์บันทึกการทำงาน (log) แจ้งว่าไม่พบ `cublas64_12.dll` | สภาพแวดล้อมเสมือนยังไม่มีแพ็กเกจ CUDA กรุณารันคำสั่ง `pip install` ในขั้นตอนที่ 2 อีกครั้ง โดยรวมแพ็กเกจ `nvidia-` ไว้ด้วย |
| การ์ดแสดงข้อผิดพลาดหลังเปิดสวิตช์ | อ่านบรรทัดท้าย ๆ ของไฟล์ `instance\whisper_worker.log` ในโฟลเดอร์โปรเจกต์ หากพบว่าพอร์ต 5057 ถูกใช้งานอยู่ แสดงว่ามี Whisper อีกชุดหนึ่งทำงานอยู่แล้ว |
| ถอดเสียงไม่สำเร็จทุกครั้งและแสดง `cannot_transcribe` ส่วนในไฟล์บันทึกหรือในหน้าต่างมีข้อความ `unexpected keyword argument 'metadata_errors'` | PyAV รุ่นใหม่เกินไป กรุณารัน `venv\Scripts\python.exe -m pip install av==18.1.0` แล้วเริ่ม Whisper ใหม่ |
| หน้าต่างแสดงข้อความ เช่น `forrtl: error (200) ... window-CLOSE event` | เป็นเรื่องปกติ ข้อความนี้แสดงขึ้นเมื่อปิดหน้าต่าง Whisper และไม่ใช่ข้อผิดพลาด |
| คำสั่งเสียงใช้งานได้แต่ช้า | Whisper ทำงานบน CPU อยู่ ดูวิธีแก้ในแถวที่สองของตารางนี้ |

หากต้องการหยุด Whisper ให้ปิดสวิตช์ในหน้าตั้งค่า หรือปิดหน้าต่างของ `start_whisper_worker.bat` จากนั้นไมโครโฟนในแชทจะกลับไปใช้ตัวถอดเสียงของเบราว์เซอร์โดยอัตโนมัติ

### ข้อมูลเกี่ยวกับโมเดล

- **แหล่งดาวน์โหลด:** <https://huggingface.co/Avocaduu14/whisper-th-large-v3-ct2> คำสั่งในขั้นตอนที่ 3 ดาวน์โหลดจากหน้านี้ หรือจะดาวน์โหลดไฟล์เองจากแท็บ "Files" ของหน้านี้ แล้วเก็บไว้ในโฟลเดอร์ `models\thai-large` ก็ได้
- **ชื่อโมเดล:** `Avocaduu14/whisper-th-large-v3-ct2` บน Hugging Face เป็นโมเดล Whisper large-v3 ที่ปรับให้เหมาะกับภาษาไทย แล้วแปลงเป็นรูปแบบ CTranslate2 ก่อนนำไปเผยแพร่ต่อ กรุณาอ่านเอกสารประกอบโมเดล (model card) เพื่อดูสัญญาอนุญาตและการให้เครดิต (เมื่อโครงการนี้เริ่มใช้ โมเดลนี้เผยแพร่ภายใต้สัญญาอนุญาต Apache-2.0)
- **เหตุผลที่เลือกโมเดลภาษาไทย:** จากการทดสอบกับเสียงที่โครงการบันทึกไว้ โมเดลนี้ถอดคำสั่งสแกนได้ถูกต้องมากกว่าตัวถอดเสียงของเบราว์เซอร์อย่างชัดเจน (8 จาก 10 คำสั่ง เทียบกับ 1 หรือ 2 จาก 10 คำสั่ง)
- **ความเป็นส่วนตัว:** เสียงไม่ถูกส่งออกนอกเครื่องและไม่ถูกจัดเก็บ โปรแกรมรับคำขอผ่าน `127.0.0.1` เท่านั้น
- **ข้อจำกัดของการทดสอบ:** คู่มือนี้เขียนตามการตั้งค่าบนเครื่องที่ใช้พัฒนา ยังไม่มีการทดสอบติดตั้งบนเครื่องใหม่โดยทำตามขั้นตอนในคู่มือนี้เพียงอย่างเดียว

---

## English

CLYLAR can turn spoken commands into text with a **local Whisper model**. It is optional. Without it the chat microphone uses the browser's own speech engine, which sends the audio to Google (Chrome) or Microsoft (Edge) and reads IP addresses less reliably.

The model is **not in this repository**: it is about 3 GB, and GitHub refuses single files over 100 MB. You download it once, from its public home on Hugging Face, into a folder on your Desktop. Nothing here needs a Google Drive copy.

### What you need

> [!IMPORTANT]
> **Use Python 3.11 or 3.13 only.** Python 3.14 does not work yet (a tester reported that the whole project fails on it). If you have 3.14 installed, install 3.13 alongside it and create the virtual environment with that version.

| | |
|---|---|
| Windows | The steps below are for Windows (the app and `start_whisper_worker.bat` are written for it). |
| **Python 3.11 or 3.13** | A separate virtual environment is used for Whisper, so it does not touch the app's Python packages. 3.14 is not supported (see the note above). |
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
venv\Scripts\python.exe -m pip install faster-whisper==1.2.1 av==18.1.0 nvidia-cublas-cu12 nvidia-cudnn-cu12
```

The two `nvidia-` packages are the CUDA libraries for the graphics card. Skip them only if you have no NVIDIA card (Whisper then runs on the CPU).

`av==18.1.0` is pinned on purpose: PyAV 19 and newer do not work with faster-whisper 1.2.1, and every transcription then fails with `cannot_transcribe`.

**3. Download the model.** It is pinned to the exact revision the project was tested with.

```bat
venv\Scripts\python.exe -c "from huggingface_hub import snapshot_download; snapshot_download('Avocaduu14/whisper-th-large-v3-ct2', revision='1a1554ea606d89c937216ada609bb8585e20a36e', local_dir='models/thai-large')"
```

It takes several minutes, depending on your internet speed. When it finishes, `models\thai-large` must hold `model.bin` (about 3 GB), `config.json`, `tokenizer.json`, `vocabulary.json` and `preprocessor_config.json`.

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
| The card says **ยังไม่ได้ติดตั้ง Whisper ในเครื่องนี้** | The app cannot find `venv\Scripts\python.exe` or `models\thai-large\model.bin` in the folder above. Check the folder name and the layout in steps 2 and 3. |
| The card says **ใช้ CPU (ช้า)** and the log says `cublas64_12.dll` was not found | The CUDA packages are missing from the environment. Run the `pip install` of step 2 again, with the `nvidia-` packages. |
| The card shows an error after you pressed the switch | Read the last lines of `instance\whisper_worker.log` in the project folder. A port already in use means another copy is running (port 5057). |
| Every transcription fails with `cannot_transcribe`, and the log or the window shows `unexpected keyword argument 'metadata_errors'` | PyAV is too new. Run `venv\Scripts\python.exe -m pip install av==18.1.0`, then start Whisper again. |
| A window with lines like `forrtl: error (200) ... window-CLOSE event` | Normal. It is printed when the Whisper window is closed. It is not an error. |
| Voice commands work but are slow | It is running on the CPU. See the second row of the table above. |

To stop Whisper, turn the switch off in Settings or close the `start_whisper_worker.bat` window. The chat microphone then goes back to the browser's engine by itself.

### About the model

- **Where to get it:** <https://huggingface.co/Avocaduu14/whisper-th-large-v3-ct2> (the command in step 3 downloads it from there; you can also download the files by hand from that page's "Files" tab into `models\thai-large`).
- **Name:** `Avocaduu14/whisper-th-large-v3-ct2` on Hugging Face, a CTranslate2 conversion of a Thai-tuned Whisper large-v3. Read its model card for the licence and credits before you redistribute it (it was Apache-2.0 when this project adopted it).
- **Why a Thai-tuned model:** on this project's own recordings it understood spoken scan commands far better than the browser's engine (8 of 10 against 1 or 2 of 10).
- **Privacy:** the audio never leaves the computer and nothing is stored. The program listens on `127.0.0.1` only.
- **Not tested here:** this guide follows the setup of the development machine. A completely clean install following only these steps has not been repeated.
