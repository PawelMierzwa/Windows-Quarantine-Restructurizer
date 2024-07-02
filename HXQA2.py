import os
import argparse
import zipfile
import hashlib
import xml.etree.ElementTree as ET
import glob
import isodate
import io
import struct
import argparse
import datetime
from datetime import datetime as dt2
import pyzipper
import pathlib
from time import sleep
import os
import hashlib
from prettytable import PrettyTable
from collections import namedtuple

def create_output_folder(output_dir):
    now = dt2.now()
    dt = now.strftime("%Y-%m-%d_%H-%M-%S")
    quarantine_folder = os.path.join(output_dir, f"Quarantine-{dt}")
    os.makedirs(quarantine_folder)
    return quarantine_folder

def unzip_archive(archive_path, output_dir, password=None):
    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
        if password:
            zip_ref.setpassword(password.encode())
        zip_ref.extractall(output_dir)

def map_md5_to_files(output_dir):
    hash_map = {}
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            if file[0].isdigit() and '.' not in file:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.md5(f.read()).hexdigest()
                hash_map[file_hash] = file
    return hash_map

def process_xml_file(xml_file, output_dir, file_map):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    for file_item in root.findall('FileItem'):
        file_path = file_item.find('FilePath').text
        md5sum = file_item.find('Md5sum').text
        if file_path.startswith('PROGRAMDATA\\MICROSOFT\\WINDOWS DEFENDER\\QUARANTINE'):
            file_path = file_path.replace('PROGRAMDATA\\MICROSOFT\\WINDOWS DEFENDER\\QUARANTINE\\', '')
            file = file_map.get(md5sum)
            if os.name == 'nt':
                slash = '\\'
            else:
                slash = '/'
            file_path = file_path.replace("\\", slash)
            if file:
                if file_path != 'Entries':
                    new_file_name = os.path.basename(file).split('-')[1][:-1]
                else: 
                    new_file_name = os.path.basename(file).split('-', 1)[1][:-1]
                file_path = os.path.join(output_dir, file_path)
                os.makedirs(file_path, exist_ok=True)
                new_file_path = os.path.join(file_path, new_file_name)
                old_file_path = os.path.join(output_dir, file)
                os.rename(old_file_path, new_file_path)

def print_system_info(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    for item in root.findall('SystemInfoItem'):
        hostname = item.find('hostname').text
        domain = item.find('domain').text
        uptime = item.find('uptime').text
        primary_ipv4_address = item.find('primaryIpv4Address').text
        mac = item.find('MAC').text
        product_name = item.find('productName').text
        build_number = item.find('buildNumber').text
        os_bitness = item.find('OSbitness').text

    print('\nSystem Information')
    print('--------------------')
    print(f'Hostname: {hostname}')
    print(f'Domain: {domain}')
    duration = isodate.parse_duration(uptime)
    hours, remainder = divmod(duration.total_seconds(), 3600)
    minutes, seconds = divmod(remainder, 60)
    print(f"Uptime: {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds")
    print(f'Primary IPv4 Address: {primary_ipv4_address}')
    print(f'MAC: {mac}')
    print(f'Operating System: {product_name} {os_bitness}, build {build_number}\n')

def mse_ksa():
    key = [
        0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
        0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
        0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
        0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
        0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
        0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
        0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
        0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
        0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
        0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
        0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
        0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
        0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
        0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
        0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
        0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
        0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
        0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
        0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
        0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
        0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
        0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
        0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
        0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
        0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD,
        0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53
    ]
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp
    return sbox

def rc4_decrypt(data):
    sbox = mse_ksa()
    out = bytearray(len(data))
    i = 0
    j = 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp
        val = sbox[(sbox[i] + sbox[j]) % 256]
        out[k] = val ^ data[k]

    return out

def unpack_malware(f):
    decrypted = rc4_decrypt(f.read())
    sd_len = struct.unpack_from('<I', decrypted, 0x8)[0]
    header_len = 0x28 + sd_len
    malfile_len = struct.unpack_from('<Q', decrypted, sd_len + 0x1C)[0]
    malfile = decrypted[header_len:header_len + malfile_len]

    return (malfile, malfile_len)

def dump_entries(basedir, entries):
    delay = 0.15
    print("\n[+] Decrypting Entries:");sleep(delay)

    now = dt2.now()
    dt = now.strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs("Decrypted", exist_ok=True)
    zipname = os.path.join("Decrypted", "released_files_" + dt + ".zip")
    secret_password = b'infected'
    zip_buffer = io.BytesIO()

    with pyzipper.AESZipFile(zip_buffer,
                         'w',
                         compression=pyzipper.ZIP_LZMA,
                         encryption=pyzipper.WZ_AES) as zip_file:
        zip_file.setpassword(secret_password)

        for file_rec in entries:
            quarfile = os.path.join(basedir, 'ResourceData', file_rec.hash[:2], file_rec.hash)

            if not pathlib.Path(quarfile).exists():
                continue

            with open(quarfile, 'rb') as f:
                print(f'[+] Decrypting \'{file_rec.path.name}\'')
                malfile, malfile_len = unpack_malware(f)

                file_name = file_rec.path.name
                data = io.BytesIO(malfile)
                zip_file.writestr(file_name, data.getvalue())

    with open(zipname, 'wb') as f:
        f.write(zip_buffer.getvalue())
    print("\n[+] Decrypted files saved to password protected .ZIP (aes256): '" + zipname + "\' (Password: infected)\n")

def get_entry(data):
    pos = data.find(b'\x00\x00\x00') + 1
    path_str = data[:pos].decode('utf-16le')

    if path_str[2:4] == '?\\':
        path_str = path_str[4:]

    path = pathlib.PureWindowsPath(path_str)

    pos += 4  # skip number of entries field
    type_len = data[pos:].find(b'\x00')
    type = data[pos:pos + type_len].decode()  # get entry Type (UTF-8)
    pos += type_len + 1
    pos += (4 - pos) % 4  # skip padding bytes
    pos += 4  # skip additional metadata
    hash = data[pos:pos + 20].hex().upper()

    return (path, hash, type)

def parse_entries(basedir):
    results = []
    for guid in glob.glob(os.path.join(basedir,'Entries/{*}')):
        with open(guid, 'rb') as f:
            header = rc4_decrypt(f.read(0x3c))
            data1_len, data2_len = struct.unpack_from('<II', header, 0x28)

            data1 = rc4_decrypt(f.read(data1_len))
            filetime, = struct.unpack('<Q', data1[0x20:0x28])
            filetime = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=filetime // 10 - 11644473600000000)
            detection = data1[0x34:].decode('utf8')

            data2 = rc4_decrypt(f.read(data2_len))
            cnt = struct.unpack_from('<I', data2)[0]
            offsets = struct.unpack_from('<' + str(cnt) + 'I', data2, 0x4)

            file_record = namedtuple("file_record", "path hash detection filetime")
            for o in offsets:
                path, hash, type = get_entry(data2[o:])
                if type == 'file':
                    results.append(file_record(path, hash, detection, filetime))

    return results

def hash_entry(hash_type, file):
    if hash_type == "sha1":
        hashs = hashlib.sha1()
    elif hash_type == "sha256":
        hashs = hashlib.sha256()
    elif hash_type == "md5":
        hashs = hashlib.md5()
    else:
        print("[-] Hash type not recognised\n")
    for chunk in iter(lambda: file.read(4096), b''):
        hashs.update(chunk)
    return hashs.hexdigest()

def main():
    delay = 0.15
    
    parser = argparse.ArgumentParser(description='HX Quarantine Analyser')
    parser.add_argument('archive_path', help='Path to the archive')
    parser.add_argument('-p', '--password', help='Password for the archive')
    parser.add_argument('-o', '--output', default='./Quarantines', help='Output folder')
    parser.add_argument('-d', '--dump', action='store_true', help='Dump the recovered files')
    parser.add_argument('-i', '--info', action='store_true', help='Display system information')
    parser.add_argument('-m', '--mode', default='md5', help='Hash type (md5, sha1, sha256)')
    args = parser.parse_args()
    
    print("""
HX Quarantine Analyser
----------------------
Author: @PawelMierzwa
Credits: @CyberGoatherder, @knez for the quarantine extraction code
    """)

    output_dir = create_output_folder(args.output)
    print("Selected Quarantine Archive: '" + args.archive_path + "'");sleep(delay)
    unzip_archive(args.archive_path, output_dir, args.password)
    file_map = map_md5_to_files(output_dir)
    xml_files = glob.glob(os.path.join(output_dir,'files-api*'))
    if xml_files:
        process_xml_file(xml_files[0], output_dir, file_map)
    else:
        print('No xml file found')
    basedir = output_dir
    entries = parse_entries(basedir)
    hash_type = args.mode.lower()
    hash_text = args.mode.upper()

    detection_max_len = max([len(x[2]) for x in entries])
    x = PrettyTable()
    x.field_names = ["Timestamp", "ThreatName", "FilePath", hash_text]
    for entry in entries:
        quarfile = os.path.join(basedir, 'ResourceData', entry.hash[:2], entry.hash)
        if not pathlib.Path(quarfile).exists():
            continue
        with open(quarfile, 'rb') as f:
            malfile, malfile_len = unpack_malware(f)
            shash = ('{}'.format(hash_entry(hash_type,io.BytesIO(malfile))))
        x.add_row([entry.filetime, f"{entry.detection:<{detection_max_len}}", entry.path, shash])
    print(x.get_string(sortby="Timestamp",reversesort=True))

    if args.dump:
        print("\nSelected Output Folder: '" + output_dir + "'");sleep(delay)
        dump_entries(output_dir, entries)
    if args.info:
        sysinfo_files = glob.glob(os.path.join(output_dir, 'sysinfo*'))
        if sysinfo_files:
            print_system_info(sysinfo_files[0])
        else:
            print('No sysinfo file found')
if __name__ == '__main__':
    main()