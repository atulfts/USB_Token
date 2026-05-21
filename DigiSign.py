import os
import sys
import fitz
import attr
import shutil
import logging
import PyKCS11
import datetime
import tkinter as tk

from threading import Thread
from endesive import pdf, hsm
from PyKCS11 import PyKCS11Lib, PyKCS11Error
from PyKCS11.LowLevel import CKA_CLASS, CKO_CERTIFICATE, CKA_LABEL

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


SERVICE = False
TOKEN_PWD = "abcd1234"
BASE_DIR = os.path.join("C:\\", "SAP", "Digi_Sign")
INPROCESS_DIR = os.path.join(BASE_DIR, "InProcess")
SUCCESS_DIR = os.path.join(BASE_DIR, "Success")
DLL_FILE = "eps2003csp11v2.dll"
DLL_PATH = os.path.join(r"C:\Windows\System32", DLL_FILE)
TICK_PATH = os.path.join(os.getcwd(), "tick.png")
FONT_PATH = os.path.join(os.getcwd(), "trebuc.ttf")
LOG_PATH = os.path.join(os.getcwd(), "dsc.log")


def exe_store(file_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, file_path)


def store_assets():
    """
    Moves all assets in the exe temp folder to exe folder
    """
    try:
        if not os.path.exists(os.path.join(os.getcwd(), "tick.png")):
            shutil.copy(exe_store("tick.png"), os.getcwd())
        # if not os.path.exists(os.path.join(os.getcwd(), DLL_FILE)):
        #     shutil.copy(exe_store(DLL_FILE), os.getcwd())
        if not os.path.exists(os.path.join(os.getcwd(), "trebuc.ttf")):
            shutil.copy(exe_store("trebuc.ttf"), os.getcwd())
    except Exception as e:
        logging.warning("1." + str(e))


def rmv(path):
    """
    @param path: Removes the file if exist
    """
    if os.path.exists(path):
        os.remove(path)


def last_page(file):
    """
    @param file: Pass full path of the file
    @return: Last page number of the pdf
    """
    pages = 1
    try:
        o_pdf = fitz.open(file)
        pages = o_pdf.page_count
        o_pdf.close()
    except Exception as e:
        logging.warning("2." + str(e))
    return pages


def sign_pdf(file, context, clshsm, signed_file="_signed.pdf"):
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
        o_signedfile = None
        with open(file, "rb") as fp:
            o_file = fp.read()
            logging.warning(f"3.0 {o_file}")
            o_signedfile = pdf.cms.sign(o_file, context, None, None, [], "sha256", clshsm)
            logging.warning(f"3.1 {o_signedfile}")
        file = file.replace(".pdf", signed_file)
        logging.warning(f"3.2 {file}")
        with open(file, "wb") as fp:
            logging.warning(f"3.3 {fp}")
            fp.write(o_file)
            fp.write(o_signedfile)
    except Exception as e:
        logging.warning("3." + str(e))


def file_processing(context):
    """
    @param context: list containing five parameters
      [
      "filename_with_ext",
      "filename_without_ext"'
      (coordinate_A,coordinate_B,oordinate_C,coordinate_D),
      signing_datetime,
      Signer_token_instance
      ]
    """
    logging.info("4.Processing file " + context[1])
    try:
        last_pg = last_page(os.path.join(INPROCESS_DIR, context[0]))
        for pg in range(0, last_pg):
            cn = context[4].cert_name()
            str_now = context[3].strftime("%Y%m%d%H%M%S+00'00'")
            ctx = {
                "aligned": 0,
                "sigflags": 3,
                "sigflagsft": 132,
                "sigpage": pg,
                "sigfield": "Signature" + str(pg),
                "auto_sigfield": True,
                "signform": False,
                "signaturebox": context[2],
                "signature_manual": [
                    [
                        "text_box",
                        f"{cn}\nDigitally Signed by: {cn}\nDate: {str_now}",
                        "default",
                        12,
                        1,
                        270,
                        40,
                        8,
                        True,
                        "left",
                        "top",
                    ],
                    ["fill_colour", 0.4, 0.4, 0.4],
                    ["rect_fill", 0, 50, 250, 1],
                    ["fill_colour", 0, 0, 0],
                    [
                        "image",
                        "tick",
                        context[2][1] * 0.3,
                        0,
                        context[2][1],
                        context[2][1] * 0.5,
                    ],
                ],
                "manual_images": {"tick": "tick.png"},
                "manual_fonts": {"DancingScript": "trebuc.ttf"},
                "contact": "",
                "location": "India",
                "signingdate": str_now,
                "reason": "",
            }

            if pg == (last_pg - 1):
                sign_pdf(os.path.join(INPROCESS_DIR, context[0]), ctx, context[4])

                # If successful signed file generated
                source_file = os.path.join(INPROCESS_DIR, context[1] + "_signed.pdf")
                dest_file = os.path.join(SUCCESS_DIR, context[1] + "_signed.pdf")

                if os.path.exists(source_file):

                    logging.debug("5.Delete Source File " + context[0])
                    rmv(os.path.join(INPROCESS_DIR, context[0]))

                    logging.debug("6.Delete Destination File " + context[1])
                    if os.path.exists(dest_file):
                        os.remove(dest_file)

                    logging.debug("7.Move to Destination File " + context[1])
                    shutil.move(source_file, SUCCESS_DIR)
                    logging.info("8.File successfully created: " + INPROCESS_DIR + "\\" + context[0])
                    print("File successfully created:", os.path.join(SUCCESS_DIR, context[1] + "_signed.pdf"))
            else:
                sign_pdf(
                    os.path.join(INPROCESS_DIR, context[0]), ctx, context[4], "_pen.pdf"
                )

                # If successful signed file gneerated
                source_file = os.path.join(INPROCESS_DIR, context[1] + "_pen.pdf")
                dest_file = os.path.join(INPROCESS_DIR, context[0])

                if os.path.exists(INPROCESS_DIR + "//" + context[1] + "_pen.pdf"):
                    logging.debug(
                        "9.Removing file " + INPROCESS_DIR + "\\" + context[0]
                    )
                    rmv(dest_file)

                    logging.debug(
                        "10.Renaming file " + context[1] + "_pen.pdf => " + context[0]
                    )
                    os.rename(source_file, dest_file)
                else:
                    break

    except Exception as e:
        logging.warning("11." + str(e))


def esign_app():
    """
    Tkinter add to capture the usb token password from the user
    """
    app = tk.Tk()
    app.title("F.T. Solutions Pvt Ltd")
    app.geometry("400x200")
    app.configure(bg="black")

    pwd_label = tk.Label(app, text="Password:", fg="white", bg="black")
    pwd_label.pack(pady=10)
    pwd = tk.Entry(app, show="*")
    pwd.pack()

    def start_service():
        global TOKEN_PWD, SERVICE
        pin = pwd.get()
        if pin:
            TOKEN_PWD = pin
        SERVICE = True
        app.destroy()

    def end_service():
        global SERVICE
        SERVICE = False
        app.destroy()

    sign_button = tk.Button(
        app, text="Start Signing", command=start_service, bg="purple", fg="white"
    )
    sign_button.pack(pady=20)

    cancel_button = tk.Button(
        app, text="Cancel", command=end_service, bg="red", fg="white"
    )
    cancel_button.pack(pady=10)

    app.mainloop()


def main():
    r"""
    Python 3.11.3

    Reads the ePass2003 token and digitally signs all the pages in the pdf with green tick
    place all the assets folder files in the root/project folder before executing or creating an exe
    Comment line 1 and add line 2 in the path listed below b4 creating exe
    1.HELVETICA_PATH = os.path.join(os.path.dirname(__file__), "..", "fonts", "Helvetica.ttf")
    2.HELVETICA_PATH = 'trebuc.ttf'

    Paths to find point 1
    venv\Lib\site-packages\endesive\pdf\PyPDF2_annotate\annotations\
        ->signature.py
        ->text.py
    @return:
    """
    global SERVICE
    # Get Token Password
    esign = Thread(target=esign_app)
    esign.start()
    log_thread = Thread(target=rmv, args=[LOG_PATH])
    log_thread.start()
    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=12)

    # Initiating Log
    log_thread.join()
    logging.basicConfig(
        filename=LOG_PATH,
        filemode="a",
        level=logging.INFO,
        format="%(message)s - %(asctime)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.critical("Hello World")
    # Cooking Assets
    Thread(target=store_assets, daemon=False).start()

    esign.join()

    if SERVICE:
        class Signer(hsm.HSM):
            def __init__(self, dllpath):
                self.pkcs11 = PyKCS11Lib()
                self.pkcs11.load(dllpath)

            def open_session(self):
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

            def cert_name(self):
                global SERVICE
                session = None

                try:
                    session = self.open_session()

                    certificates = session.findObjects([
                        (CKA_CLASS, CKO_CERTIFICATE)
                    ])

                    for cert in certificates:

                        # Get certificate binary
                        cert_der = bytes(session.getAttributeValue(
                            cert,
                            [PyKCS11.CKA_VALUE]
                        )[0])


                        x509_cert = x509.load_der_x509_certificate(
                            cert_der,
                            default_backend()
                        )

                        cn = x509_cert.subject.get_attributes_for_oid(
                            NameOID.COMMON_NAME
                        )[0].value

                        print("Certificate Name:", cn)

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
            for path_to, directories, files in os.walk(INPROCESS_DIR):
                for filename_ext in files:
                    file_name, file_ext = os.path.splitext(filename_ext)
                    if filename_ext and file_ext.lower() == ".pdf":
                        try:
                            logging.info(
                                "14." + str(INPROCESS_DIR + "\\" + filename_ext)
                            )
                            ab_list = file_name.split("_")
                            cord_a = int(ab_list[-1])
                            cord_b = int(ab_list[-2])
                            cord_c = cord_a + 130
                            cord_d = cord_b + 40
                            context = [
                                filename_ext,
                                file_name,
                                (cord_a, cord_b, cord_c, cord_d),
                                now,
                                clshsm,
                            ]
                            file_processing(context)
                        except Exception as e:
                            logging.warning("15." + str(e))
                        continue
        except Exception as e:
            logging.warning("13." + str(e))


if __name__ == "__main__":
    main()
    rmv(TICK_PATH)
    #rmv(DLL_PATH)
    rmv(FONT_PATH)
