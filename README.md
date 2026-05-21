# DSC PDF Signing Tool

A Python-based Digital Signature Certificate (DSC) PDF signing tool that allows users to digitally sign PDF documents using USB Token certificates.

---

# Features

- Sign PDF files using DSC USB Token
- Add visible signature with:
  - Name
  - Date & Time
  - Tick image
  - Custom text
- Support for manual signature positioning
- EXE build support using PyInstaller
- History logging
- SHA256 signing
- PDF CMS signing support

---

# Requirements

- Python 3.10+
- Windows OS 10
- Valid DSC USB Token
- Installed Token Driver

---

# Install Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install endesive pillow pyhanko reportlab
```

---

# Project Structure

```bash
project/
│
├── main.py
├── tick.png
├── requirements.txt
├── README.md
├── eps2003csp11v2.dll
└── output/
```

---

# USB Token Setup

1. Insert DSC USB Token
2. Install token driver software
3. Ensure DLL file exists:

```bash
eps2003csp11v2.dll
```

4. Verify certificate is visible in Windows Certificate Manager

---

# Run Project

```bash
python main.py
```

---

# Build EXE

Basic build:

```bash
pyinstaller --onefile --add-binary "eps2003csp11v2.dll;." main.py
```

Build with image support:

```bash
pyinstaller --onefile ^
--add-data "tick.png;." ^
--add-binary "eps2003csp11v2.dll;." ^
main.py
```

---

# Signature Configuration Example

```python
"signature_manual": [
    [
        "image",
        "tick",
        85,
        240,
        50,
        6,
    ],

    [
        "text_box",
        f"Digitally Signed by: {cn}\nDate: {str_now}",
        "default",
        12,
        1,
        270,
        40,
        8,
        True,
        "left",
        "top",
    ]
]
```

---

# Common Errors

## DLL Not Found

Error:

```bash
No such file or directory: eps2003csp11v2.dll
```

Fix:

```bash
--add-binary "eps2003csp11v2.dll;."
```

Or place DLL near EXE file.

---

## NoneType has no attribute write

Possible reasons:

- USB token not connected
- Certificate not selected
- Invalid PDF path

---

## Signature Line or Extra Space

Adjust coordinates:

```python
cord_c = cord_a + 260
cord_d = cord_b + 75
```

Reduce width/height if extra spacing appears.

---

# Output

Signed PDF files will be generated inside:

```bash
output/
```

Example:

```bash
invoice_signed.pdf
```

---

# Logging

Example logs:

```bash
Hello World
File is successfully created
```

Logs include:

- Certificate details
- Signing status
- Errors
- File generation status

---

# Git Commands

Initialize git:

```bash
git init
```

Commit:

```bash
git add .
git commit -m "Initial Commit"
```

Push to GitHub:

```bash
git remote add origin https://github.com/atulfts/USB_Token.git
git push -u origin master
```

---

# Author

Created by Atul Yadav

---

# License

MIT License
