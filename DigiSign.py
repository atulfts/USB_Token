import sys
import fitz
import attr
import psutil
import base64
import pickle
import shutil
import logging
import PyKCS11
import datetime
import argparse
import tkinter as tk

from pathlib import Path
from threading import Thread
from endesive import pdf, hsm
from PyKCS11 import PyKCS11Lib, PyKCS11Error
from PyKCS11.LowLevel import CKA_CLASS, CKO_CERTIFICATE

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

SERVICE = False
LOG_FILE = "dsc.log"
TOKEN_PWD = "abcd1234"
CFG_FILE = "stor.pkl"
TICK_FILE = "tick.png"
FONT_FILE = "trebuc.ttf"
FT_LOGO_FILE = "logo.png"
DLL_FILE = "eps2003csp11v2.dll"
PDF_DIR = "InProcess"
SIGNED_PDF_DIR = "Success"

BASE_DIR = Path(r"C:\SAP\Digi_Sign")
CFG_PATH = BASE_DIR / CFG_FILE
IN_DIR = BASE_DIR / PDF_DIR
OUT_DIR = BASE_DIR / SIGNED_PDF_DIR
OUT_DIR.mkdir(parents=True, exist_ok=True)
DLL_PATH = BASE_DIR / DLL_FILE
TICK_PATH = BASE_DIR / TICK_FILE
FONT_PATH = BASE_DIR / FONT_FILE
LOGO_PATH = BASE_DIR / FT_LOGO_FILE
LOG_PATH = BASE_DIR / LOG_FILE


logging.basicConfig(
    filename=str(LOG_PATH),
    filemode="a",
    level=logging.DEBUG,
    format="%(asctime)s|%(levelname)s|%(funcName)s|%(lineno)d|%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def rmv(path: Path):
    try:
        if path.exists():
            path.unlink()
    except Exception as err:
        logging.critical(f"{err}")


def load_config():
    """Return (saved_flags, saved_password) from pickle. Both default to empty/None on error."""
    if CFG_PATH.exists():
        logging.debug(f"Config Found")
        try:
            with open(CFG_PATH, "rb") as fil:
                data = pickle.load(fil)
                logging.debug(f"Config Read")

            if isinstance(data, dict):
                flag, password = data.get("flags", []), data.get("password")
                logging.debug(f"Flag: {flag}|Password: ******")
                return flag, password

            if isinstance(data, list):
                logging.debug(f"Flag: {data}|Password: {None}")
                return data, None
        except Exception as err:
            logging.critical(f"{err}")
    else:
        logging.debug(f"Config Not Found")

    return [], None


def exe_store(filename: Path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    base_path = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    logging.debug(f"{base_path}")
    src_dir = str(base_path / filename)
    logging.debug(f"{src_dir}")
    return src_dir


def store_assets():
    """
    Copies required assets from the executable temp folder to BASE_DIR.
    Uses BASE_DIR (not cwd) so the path is stable regardless of which
    process launched the exe and what cwd that process set.
    """
    for filepath in (TICK_PATH, DLL_PATH, FONT_PATH, LOGO_PATH):
        try:
            if not filepath.exists():
                shutil.copy2(exe_store(filepath.name), str(filepath))
                logging.info("Copied %s -> %s", filepath.name, filepath)
                continue
            logging.info("Exist %s", filepath)
        except Exception as err:
            logging.critical(f"{filepath.name}|{err}")


def last_page(filename: Path):
    """
    @param file: Pass full path of the file
    @return: Last page number of the pdf
    """
    pages = 1
    try:
        pdf = fitz.open(str(filename))
        pages = pdf.page_count
        pdf.close()
    except Exception as err:
        logging.critical(f"{err}")
    logging.info(f"Last Page No: {pages}")
    return pages


def sign_pdf(file: Path, ctx, clshsm):
    """
    @param file: pass path/to/filename.ext
    @param context: list containing five parameters
    [
      "filename_with_ext",
      "filename_without_ext"'
      (coordinate_A,coordinate_B,oordinate_C,coordinate_D),
      signing_datetime,
      Signer_token_instance
      ]
    @param clshsm: pass the Signer instance of the token
    @param signed_file: appending name of the output file
    """
    try:
        signedData = None
        with open(str(file), "rb") as fp:
            filedata = fp.read()
            signedData = pdf.cms.sign(
                filedata, ctx, None, None, [], "sha256", clshsm
            )
            logging.info(f"{file.name}")

        with open(str(file), "wb") as fp:
            fp.write(filedata)
            fp.write(signedData)
            logging.info(f"Saved {file.name}")
    except Exception as err:
        logging.critical(f"{err}")


def processingFile(file_path, cordinates, timestamp, clshsm):
    """
    @param context: list containing five parameters
      [
      "filename_with_ext",
      (coordinate_A,coordinate_B,oordinate_C,coordinate_D),
      signing_datetime,
      Signer_token_instance
      ]
    """
    logging.debug(f"{file_path.name}")
    try:
        last_pg = last_page(file_path)
        cn = clshsm.cert_name()
        cn = (cn.split()[-1] + "\n" + " ".join(cn.split()[:-1])) if len(cn) > 18 else cn
        str_now = timestamp.strftime("%Y%m%d%H%M%S+00'00'")
        for pg in range(0, last_pg):
            ctx = {
                "aligned": 0,
                "sigflags": 3,
                "sigflagsft": 132,
                "sigpage": pg,
                "sigfield": "Signature" + str(pg),
                "auto_sigfield": True,
                "signform": False,
                "signaturebox": cordinates,
                "signature_manual": [
                    [
                        "image",
                        "tick",
                        85,   # center X
                        2,    # top
                        40,   # width
                        40,   # height
                    ],
                    [
                        "text_box",
                        f"\n \n \nDigitally Signed by:{cn}\nDate: {str_now}",
                        "default",
                        10,
                        1,
                        170,
                        50,
                        6,
                        True,
                        "left",
                        "top",
                    ],
                    ["fill_colour", 0.4, 0.4, 0.4],
                ],
                "manual_images": {"tick": str(TICK_PATH)},
                "manual_fonts": {"DancingScript": str(FONT_PATH)},
                "contact": "",
                "location": "India",
                "signingdate": str_now,
                "reason": "",
            }

            sign_pdf(file_path, ctx, clshsm)

            if pg == (last_pg - 1):
                source_file = file_path
                dest_file = OUT_DIR / Path(file_path.stem + "_signed.pdf")

                if source_file.exists():
                    shutil.move(str(source_file), str(dest_file))

    except Exception as err:
        logging.critical(f"{err}")


def load_logo():
    """
    Loads logo.png from next to the script or BASE_DIR.
    Scales to fit within 200 x 70 px, preserving aspect ratio.
    Returns a tk.PhotoImage, or None if no logo file is found.
    """
    if LOGO_PATH.exists():
        logging.debug(f"{LOGO_PATH} exist")
        try:
            doc = fitz.open(str(LOGO_PATH))
            page = doc[0]
            w, h = page.rect.width, page.rect.height
            scale = min(200 / w, 70 / h, 2.0)
            pix = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=True)
            doc.close()
            logo = tk.PhotoImage(data=base64.b64encode(pix.tobytes("png")).decode())
            logging.info("Logo Loaded")
            return logo
        except Exception as err:
            logging.critical(f"{err}")
    logging.critical("None")
    return None


def esign_app():
    """
    Tkinter dialog to capture the USB token PIN from the user.
    """
    # ── Light theme palette ───────────────────────────────────────────────────
    BG = "#f9fafb"
    HEADER_BG = "#ffffff"
    INPUT_BG = "#ffffff"
    BORDER = "#d1d5db"
    ACCENT = "#2563eb"
    ACCENT_H = "#1d4ed8"
    FG_MAIN = "#111827"
    FG_DIM = "#6b7280"
    ERR_FG = "#dc2626"
    BTN_SEC_BG = "#f3f4f6"
    BTN_SEC_FG = "#374151"

    app = tk.Tk()
    app.title("F.T. Solutions – Digital Signing")
    app.resizable(False, False)
    app.configure(bg=BG)

    W, H = 420, 320
    app.update_idletasks()
    x = (app.winfo_screenwidth() - W) // 2
    y = (app.winfo_screenheight() - H) // 2
    app.geometry(f"{W}x{H}+{x}+{y}")

    app.attributes("-topmost", True)
    app.after(200, lambda: app.attributes("-topmost", False))

    header = tk.Frame(app, bg=HEADER_BG, pady=20)
    header.pack(fill="x")

    logo_photo = load_logo()
    if logo_photo:
        lbl = tk.Label(header, image=logo_photo, bg=HEADER_BG)
        lbl.image = logo_photo
        lbl.pack()
    else:
        tk.Label(
            header,
            text="F.T. Solutions Pvt Ltd",
            font=("Segoe UI", 14, "bold"),
            fg=ACCENT,
            bg=HEADER_BG,
        ).pack()

    tk.Label(
        header,
        text="USB Token Authentication",
        font=("Segoe UI", 9),
        fg=FG_DIM,
        bg=HEADER_BG,
    ).pack(pady=(4, 0))

    tk.Frame(app, bg=BORDER, height=1).pack(fill="x")

    body = tk.Frame(app, bg=BG, padx=40, pady=24)
    body.pack(fill="both", expand=True)

    tk.Label(
        body,
        text="Token PIN / Password",
        font=("Segoe UI", 9, "bold"),
        fg=FG_MAIN,
        bg=BG,
    ).pack(anchor="w")

    # Bordered input row
    border_frame = tk.Frame(body, bg=BORDER)
    border_frame.pack(fill="x", pady=(6, 0))
    input_row = tk.Frame(border_frame, bg=INPUT_BG)
    input_row.pack(fill="x", padx=1, pady=1)

    pwd = tk.Entry(
        input_row,
        show="●",
        font=("Segoe UI", 11),
        bg=INPUT_BG,
        fg=FG_MAIN,
        bd=0,
        relief="flat",
        insertbackground=FG_MAIN,
    )
    pwd.pack(side="left", fill="x", expand=True, ipady=9, padx=(10, 0))

    visible = tk.BooleanVar(value=False)

    def toggle_visibility():
        if visible.get():
            pwd.config(show="●")
            eye_btn.config(text="\U0001f441")
            visible.set(False)
        else:
            pwd.config(show="")
            eye_btn.config(text="\U0001f648")
            visible.set(True)

    eye_btn = tk.Button(
        input_row,
        text="\U0001f441",
        command=toggle_visibility,
        bg=INPUT_BG,
        fg=FG_DIM,
        bd=0,
        relief="flat",
        font=("Segoe UI", 11),
        cursor="hand2",
        activebackground=INPUT_BG,
    )
    eye_btn.pack(side="right", padx=6)

    err_label = tk.Label(body, text="", font=("Segoe UI", 8), fg=ERR_FG, bg=BG)
    err_label.pack(anchor="w", pady=(6, 0))

    btn_row = tk.Frame(body, bg=BG)
    btn_row.pack(fill="x", pady=(8, 0))

    def start_service():
        global TOKEN_PWD, SERVICE
        pin = pwd.get().strip()
        if not pin:
            err_label.config(text="PIN cannot be empty.")
            pwd.focus_set()
            return
        TOKEN_PWD = pin
        SERVICE = True
        app.destroy()

    def end_service():
        global SERVICE
        SERVICE = False
        app.destroy()

    tk.Button(
        btn_row,
        text="Cancel",
        command=end_service,
        bg=BTN_SEC_BG,
        fg=BTN_SEC_FG,
        bd=0,
        relief="flat",
        font=("Segoe UI", 10),
        cursor="hand2",
        padx=18,
        pady=7,
        activebackground="#e5e7eb",
    ).pack(side="right", padx=(8, 0))

    tk.Button(
        btn_row,
        text="Start Signing",
        command=start_service,
        bg=ACCENT,
        fg="#ffffff",
        bd=0,
        relief="flat",
        font=("Segoe UI", 10, "bold"),
        cursor="hand2",
        padx=18,
        pady=7,
        activebackground=ACCENT_H,
    ).pack(side="right")

    app.bind("<Return>", lambda _: start_service())
    app.bind("<Escape>", lambda _: end_service())
    pwd.focus_set()
    app.mainloop()


def main():
    r"""
    Python 3.11.3

    Reads the ePass2003 token and digitally signs all the pages in the pdf with green tick
    place all the assets folder files in the root/project folder before executing or creating an exe
    Comment line 1 and add line 2 in the path listed below b4 creating exe
    1.HELVETICA_PATH = os.path.join(os.path.dirname(__file__), "..", "fonts", "Helvetica.ttf")
    2.HELVETICA_PATH = os.path.join(r"C:\SAP\Digi_Sign", "trebuc.ttf")

    Paths to find point 1
    venv\Lib\site-packages\endesive\pdf\PyPDF2_annotate\annotations\
        ->signature.py
        ->text.py
    @return:
    """
    global SERVICE, TOKEN_PWD

    args = _parse_args()
    saved_flags, saved_password = load_config()
    logging.getLogger().setLevel(logging.DEBUG if args.v else logging.INFO)
    logging.critical("FTSPL - DIGISIGN")

    store_assets()
    if args.e:
        logging.info("Assets extracted: %s", BASE_DIR)
        return

    if args.r:
        rmv(CFG_PATH)
        logging.info("Cleared Config")
        saved_flags, saved_password = [], None

    flags_to_save = []
    if args.s:
        if args.v:
            flags_to_save.append("-v")
        if args.a:
            flags_to_save.append("-a")
        if args.c:
            flags_to_save.append("-c")
        if args.r:
            flags_to_save.append("-r")
        if args.e:
            flags_to_save.append("-e")

    if args.a and saved_password:
        TOKEN_PWD, SERVICE = saved_password, True
    else:
        esign = Thread(target=esign_app)
        esign.start()
        esign.join()

    if SERVICE:
        class Signer(hsm.HSM):
            def __init__(self, dllpath):
                self.pkcs11 = PyKCS11Lib()
                self.pkcs11.load(str(dllpath))

            def open_session(self):
                try:
                    slots = [
                        slot
                        for slot in self.pkcs11.getSlotList(tokenPresent=True)
                        if self.pkcs11.getTokenInfo(slot)
                    ]

                    if not slots:
                        raise Exception("USB Token not detected")

                    slot = slots[0]
                    session = self.pkcs11.openSession(slot)
                    session.login(TOKEN_PWD)
                    return session
                except Exception as err:
                    logging.critical(f"{err}")


            def cert_name(self):
                global SERVICE
                session = None

                try:
                    session = self.open_session()

                    certificates = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])

                    for cert in certificates:

                        # Get certificate binary
                        cert_der = bytes(
                            session.getAttributeValue(cert, [PyKCS11.CKA_VALUE])[0]
                        )

                        x509_cert = x509.load_der_x509_certificate(
                            cert_der, default_backend()
                        )

                        cn = x509_cert.subject.get_attributes_for_oid(
                            NameOID.COMMON_NAME
                        )[0].value

                        logging.critical(f"Certificate Name: {cn}")

                        return cn

                    return "Unknown User"

                except PyKCS11Error as e:
                    logging.warning("12." + str(e))
                    SERVICE = False
                    return "USB Token Error"

                finally:
                    try:
                        if session:
                            session.logout()
                            session.closeSession()
                    except:
                        pass

            def certificate(self):
                session = None
                try:
                    session = self.open_session()
                    pk11objects = session.findObjects(
                        [(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]
                    )

                    all_attributes = [
                        PyKCS11.CKA_VALUE,
                        PyKCS11.CKA_ID,
                    ]

                    for pk11object in pk11objects:
                        try:
                            attributes = session.getAttributeValue(
                                pk11object, all_attributes
                            )
                        except PyKCS11.PyKCS11Error:
                            continue

                        attr_dict = dict(zip(all_attributes, attributes))
                        cert = bytes(attr_dict[PyKCS11.CKA_VALUE])
                        return bytes(attr_dict[PyKCS11.CKA_ID]), cert

                finally:
                    try:
                        if session:
                            session.logout()
                            session.closeSession()
                    except:
                        pass

                return None, None

            def sign(self, keyid, data, mech):
                session = None
                try:
                    session = self.open_session()
                    priv_key = session.findObjects(
                        [
                            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                            (PyKCS11.CKA_ID, keyid),
                        ]
                    )[0]
                    mech = getattr(PyKCS11, "CKM_%s_RSA_PKCS" % mech.upper())
                    signature = session.sign(
                        priv_key, data, PyKCS11.Mechanism(mech, None)
                    )
                    return bytes(signature)
                
                finally:
                    try:
                        if session:
                            session.logout()
                            session.closeSession()
                    except:
                        pass

        try:
            clshsm = Signer(DLL_PATH)
            pdf_files = list(IN_DIR.glob("*.pdf"))
            logging.info(f"PDFs: {pdf_files}")
            for file_path in pdf_files:
                now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=12)
                logging.info(f"{file_path.name}")
                file_name = file_path.stem
                ab_list = file_name.split("_")
                cord_a = int(ab_list[-1])
                cord_b = int(ab_list[-2])
                cord_c = cord_a + 180
                cord_d = cord_b + 40
                processingFile(
                        file_path,
                        (cord_a, cord_b, cord_c, cord_d),
                        now,
                        clshsm,
                )
            del clshsm
        except Exception as err:
            logging.critical(f"{err}")

        if args.a:
            persist_flags = (
                flags_to_save if flags_to_save is not None else list(saved_flags)
            )
            if "-a" not in persist_flags:
                persist_flags.append("-a")
            try:
                with open(CFG_PATH, "wb") as f:
                    pickle.dump(
                        {
                            "flags": persist_flags,
                            "password": TOKEN_PWD if SERVICE else saved_password,
                        },
                        f,
                    )
                    logging.info(f"Password saved")
            except Exception as err:
                logging.critical(f"{err}")
    
    if not args.c:
        cleanup()


def cleanup():
    for i in (TICK_PATH, DLL_PATH, FONT_PATH, LOGO_PATH):
        rmv(i)


def _parse_args():
    """
    Merge saved flags (from pickle) with current sys.argv, then parse.
    Saved flags act as defaults; flags passed on the command line take effect too.
    """
    saved_flags, _ = load_config()
    combined = saved_flags + sys.argv[1:]

    parser = argparse.ArgumentParser(
        description=(
            "========================\n"
            "𝖥.𝖳. 𝖲𝗈𝗅𝗎𝗍𝗂𝗈𝗇𝗌 𝖯𝗏𝗍. 𝖫𝗍𝖽.\n"
            "𝖡𝖺𝗅𝖺𝗃𝗂 𝖨𝗇𝖿𝗈𝗍𝖾𝖼𝗁 𝖯𝖺𝗋𝗄, 𝟥𝟢𝟣, 𝖱𝖽 𝖭𝗎𝗆𝖻𝖾𝗋 𝟣𝟨𝖠,\n"
            "𝖠𝗆𝖻𝗂𝖼𝖺 𝖭𝖺𝗀𝖺𝗋, 𝖶𝖺𝗀𝗅𝖾 𝖨𝗇𝖽𝗎𝗌𝗍𝗋𝗂𝖺𝗅 𝖤𝗌𝗍𝖺𝗍𝖾\n"
            "𝖳𝗁𝖺𝗇𝖾 𝖶𝖾𝗌𝗍, 𝖬𝖺𝗁𝖺𝗋𝖺𝗌𝗁𝗍𝗋𝖺 𝟦𝟢𝟢𝟨𝟢𝟦\n"
            "========================\n"
            "DigiSign – USB Token PDF Signing Tool\n"
            "Digitally signs all PDF files found in the InProcess folder using\n"
            "an ePass2003 USB token and moves signed files to the Success folder."
        ),
        epilog=(
            "Examples:\n"
            "  DigiSign.exe              Run with GUI PIN prompt and cleanup after signing\n"
            "  DigiSign.exe -a -s        GUI prompt, save PIN + flag; future runs skip GUI\n"
            "  DigiSign.exe -v -s        Debug logging saved for all future runs\n"
            "  DigiSign.exe -c           Run without cleanup (keep assets after signing)\n"
            "  DigiSign.exe -c -s        Save -c so cleanup is always skipped\n"
            "  DigiSign.exe -r           Clear all saved arguments and reset to defaults\n"
            "  DigiSign.exe -e           Extract bundled assets to working directory and exit\n"
            "\n"
            "Note: -s persists all active flags for the next run (except -h).\n"
            "      Saved arguments are stored in: " + str(CFG_PATH)
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v", action="store_true", help="Enable DEBUG-level logging (default: INFO)"
    )
    parser.add_argument(
        "-s",
        action="store_true",
        help="Save all current arguments to disk so they are reused on the next run (works with all flags except -h)",
    )
    parser.add_argument(
        "-r",
        action="store_true",
        help="Delete the saved-arguments pickle file and reset to defaults",
    )
    parser.add_argument(
        "-a",
        action="store_true",
        help="Auto-password mode: collect PIN via GUI, save it after signing; skip GUI on subsequent runs",
    )
    parser.add_argument(
        "-c",
        action="store_true",
        help="Cancel post-signing cleanup (assets are kept); default is to remove assets after signing",
    )
    parser.add_argument(
        "-e",
        action="store_true",
        help="Extract/copy bundled assets to the working directory and exit",
    )
    return parser.parse_args(combined)


if __name__ == "__main__":
    try:
        parent = psutil.Process().parent()
        parent_info = f"{parent.name()} (pid={parent.pid})" if parent else "unknown"
    except Exception as err:
        logging.critical(f"{err}")

    logging.debug(
        "System|cwd=%s|exe=%s|parent=%s",
        Path.cwd(),
        sys.executable,
        parent_info,
    )
    main()
