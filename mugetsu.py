import os
import re
import argparse
import hashlib
import requests
import datetime
import time
import lief
import base64
import ipapi
import subprocess
import pefile


# Color codes for output
COLOR_RED = "\033[1;31m"
COLOR_GREEN = "\033[1;32m"
COLOR_YELLOW = "\033[1;33m"
COLOR_CYAN = "\033[1;36m"
COLOR_RESET = "\033[0m"

# VirusTotal API key
API_KEY = "2f9c804dba22765c3bba6be3c2ddf7e2cc9711c8e8e91afca2ee3a29ba4c7b42"


ascii_art = """

 ███▄ ▄███▓ █    ██   ▄████ ▓█████▄▄▄█████▓  ██████  █    ██ 
▓██▒▀█▀ ██▒ ██  ▓██▒ ██▒ ▀█▒▓█   ▀▓  ██▒ ▓▒▒██    ▒  ██  ▓██▒
▓██    ▓██░▓██  ▒██░▒██░▄▄▄░▒███  ▒ ▓██░ ▒░░ ▓██▄   ▓██  ▒██░
▒██    ▒██ ▓▓█  ░██░░▓█  ██▓▒▓█  ▄░ ▓██▓ ░   ▒   ██▒▓▓█  ░██░
▒██▒   ░██▒▒▒█████▓ ░▒▓███▀▒░▒████▒ ▒██▒ ░ ▒██████▒▒▒▒█████▓ 
░ ▒░   ░  ░░▒▓▒ ▒ ▒  ░▒   ▒ ░░ ▒░ ░ ▒ ░░   ▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ 
░  ░      ░░░▒░ ░ ░   ░   ░  ░ ░  ░   ░    ░ ░▒  ░ ░░░▒░ ░ ░ 
░      ░    ░░░ ░ ░ ░ ░   ░    ░    ░      ░  ░  ░   ░░░ ░ ░ 
       ░      ░           ░    ░  ░              ░     ░     
                                                          """
print(ascii_art)

def analyze_hash_virustotal(file_hash):
    try:
        params = {"apikey": API_KEY, "resource": file_hash}
        response = requests.get(
            "https://www.virustotal.com/vtapi/v2/file/report", params=params
        )
        if response.status_code == 200:
            result = response.json()
            if result["response_code"] == 1:
                print("VirusTotal scan results:")
                malicious_vendors = [
                    vendor
                    for vendor, scan_result in result["scans"].items()
                    if scan_result["detected"]
                ]
                for vendor, scan_result in result["scans"].items():
                    if scan_result["detected"]:
                        print(
                            f"{COLOR_RED}{vendor}:{COLOR_RESET} {scan_result['result']}"
                        )
                print(
                    f"{COLOR_RED}Total Malicious Vendors: {len(malicious_vendors)}{COLOR_RESET}"
                )
                return True  # Scan results found
            else:
                # No scan results available
                return False
        else:
            print("Error analyzing file hash on VirusTotal.")
            return False
    except Exception as e:
        print(f"Error analyzing file hash: {e}")
        return False





def detect_packer_obfuscation(file_path):
    try:
        print("Checking for packers and obfuscation techniques...")
        binary = lief.parse(file_path)
        if binary is not None:
            if binary.has_resources:
                print("Suspicious features detected: Resources")
            if binary.has_debug and binary.debug:  # Check if the list is not empty
                for dbg in binary.debug:
                    if isinstance(dbg, lief.DEBUG):  # Check if the object is an instance of Debug
                        if hasattr(dbg, "entries"):
                            print("Suspicious features detected: Debug information")
                            break
            if binary.has_signature:
                print("The binary is digitally signed, which might indicate a legitimate file.")
            # Check for common packers and obfuscators
            detected_packers = detect_common_packers(binary)
            if detected_packers:
                print("Detected packers/obfuscators:", ", ".join(detected_packers))
            else:
                print("No common packers or obfuscators detected.")
        else:
            print("Failed to parse the binary.")
    except Exception as e:
        print(f"Error detecting packers and obfuscation: {e}")

def detect_common_packers(binary):
    packers_obfuscators = ["UPX", "VMProtect", "Themida", "Enigma", "MPRESS", "ASPack", "Obsidium"]
    detected_packers = []
    for packer in packers_obfuscators:
        if binary.signature.has_signature(packer):
            detected_packers.append(packer)
    return detected_packers



def analyze_exe(file_path):
    file_name = os.path.basename(file_path)
    print("\n-----------------------------------Quick Metadata Analyzing:-----------------------------------\n")
    print(f"Analyzing {file_name}:")
    if not file_path.lower().endswith(".exe"):
        print("Not an executable file.")
        return

    # File metadata
    file_size = os.path.getsize(file_path)
    try:
        created_time = datetime.datetime.fromtimestamp(os.path.getctime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
    except OSError:
        created_time = "Error retrieving creation time."
    print(f"File size: {file_size} bytes")
    print(f"Created time: {created_time}")

    # File hash
    print("Calculating file hash:")
    try:
        with open(file_path, "rb") as f:
            hasher = hashlib.sha256()  # Using SHA-256 for better security
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
        print(f"File hash: {file_hash}")
        print("Analyzing file hash on VirusTotal:")
        analyze_hash_virustotal(file_hash)  # Uncomment this line
    except Exception as e:
        print(f"Error analyzing file hash: {e}")

    # Packer and obfuscation checks
    print("Checking for packers and obfuscation techniques...")
    try:
        pe = pefile.PE(file_path)
        has_resources = hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE')
        has_debug_info = hasattr(pe, 'DIRECTORY_ENTRY_DEBUG')

        if has_resources or has_debug_info:
            print("Suspicious features detected:")
            if has_resources:
                print("Resources:")
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.name is not None:
                        try:
                            name = resource_type.name.decode()
                        except AttributeError:
                            name = str(resource_type.name)
                    else:
                        name = str(resource_type.struct.Id)
                    print(f"- {name}")
            if has_debug_info:
                print("Debug information:")
                for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
                    print(f"- {debug_entry.struct}")
        else:
            print("No suspicious features detected.")

        # Identify imported functions
        # Known malicious or suspicious functions often used in malware
        malicious_functions = {
            'CreateRemoteThread', 'CreateProcess', 'WinExec', 'ShellExecute', 'HttpSendRequest',
            'InternetReadFile', 'InternetConnect', 'RegCreateKey', 'RegSetValue', 'VirtualAllocEx',
            'WriteProcessMemory', 'ReadProcessMemory', 'CreateFile', 'CreateFileMapping',
            'MapViewOfFile', 'AdjustTokenPrivileges', 'FindWindow', 'SetWindowsHookEx',
            'GetProcAddress', 'LoadLibrary', 'CryptoAPI'
        }

        # Identify imported functions
        print("Identifying famous imported functions used in malware:")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            imported_functions = set()
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    func_name = imp.name.decode("utf-8", "ignore") if imp.name else "unnamed function"
                    if func_name in malicious_functions:
                        imported_functions.add(func_name)
            if imported_functions:
                print("Famous malicious imported functions detected:")
                for func in imported_functions:
                    print(f"- {func}")
            else:
                print("No known famous malicious imported functions found.")
        else:
            print("No import directory found.")

    except Exception as e:
        print(f"Error detecting packers and obfuscation: {e}")





def analyze_python(file_path):
    file_name = os.path.basename(file_path)
    print("\n\033[34m--------------------------Quick Metadata, Content, Hash and Code Feature Analyzing:--------------------------\033[0m\n")
    print(f"Analyzing {file_name}..:")
    file_size = os.path.getsize(file_path)
    created_time = datetime.datetime.fromtimestamp(
        os.path.getctime(file_path)
    ).strftime("%Y-%m-%d %H:%M:%S")
    print(f"File size: {file_size} bytes")
    print(f"Created time: {created_time}")
    print("Calculating file hash:")
    try:
        with open(file_path, "rb") as f:
            hasher = hashlib.md5()
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
        print(f"File hash: {file_hash}")
        scan_results_found = analyze_hash_virustotal(file_hash)
        if not scan_results_found:
            print("No scan results available on VirusTotal.")
    except Exception as e:
        print(f"Error analyzing file hash: {e}")
    malicious_activities = []
    try:
        with open(file_path, "r") as f:
            contents = f.read()
            data_transmission_matches = re.finditer(
                r'urlretrieve\([\'"](http[^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\)',
                contents,
            )
            for match in data_transmission_matches:
                url = match.group(1)
                destination = match.group(2)
                malicious_activities.append(
                    (f"Downloading from {url}", f"Destination: {destination}")
                )
            ip_port_matches = re.finditer(
                r"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b):(\d+)", contents
            )
            for match in ip_port_matches:
                ip_address = match.group(1)
                port = match.group(2)
                country = get_country_info(ip_address)
                country_info = f"Originating from {country}" if country else "Country information not available"
                malicious_activities.append(
	    (
		f"IP address {ip_address}: Connecting on port {port}",
		"",
	    )
	)

                # Check IP reputation on VirusTotal
                vt_result = analyze_hash_virustotal(ip_address)
                if vt_result and vt_result.get("response_code", 0) == 1:
                    if any(scan_result.get("detected", False) for scan_result in vt_result["scans"].values()):
                        print(f"{COLOR_RED}VirusTotal indicates this IP has malicious activity.{COLOR_RESET}")
                        for vendor, scan_result in vt_result["scans"].items():
                            if scan_result['detected']:
                                print(f"{COLOR_RED}{vendor}:{COLOR_RESET} {scan_result['result']}")
                
            if malicious_activities:
                print(
                    f"{COLOR_RED}\nPotential Malicious activity detected in {file_name}:{COLOR_RESET}"
                )
                for activity, details in malicious_activities:
                    print(f"{COLOR_YELLOW} - {activity}{details}{COLOR_RESET}")
            else:
                print(
                    f"{COLOR_GREEN}No malicious activity detected in {file_name}{COLOR_RESET}"
                )
    except Exception as e:
        print(f"Error analyzing Python code: {e}")

    # Extract Strings function
    extracted_strings = extract_strings(file_path)
    if extracted_strings:
        print("Analyzing extracted strings for indicators of malicious activity...")
        # Add your analysis code here




def analyze_file(file_path):
    file_name = os.path.basename(file_path)
    malicious_activities = []
    try:
        with open(file_path, "r") as file:
            contents = file.read()
            data_transmission_matches = re.finditer(
                r"(password|credit card|ssn)", contents, re.IGNORECASE
            )
            for match in data_transmission_matches:
                malicious_activities.append(
                    (match.group(0), f"Data exfiltration at position {match.start()}")
                )
            download_matches = re.finditer(
                r'urlretrieve\([\'"](http[^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\)',
                contents,
            )
            for match in download_matches:
                url = match.group(1)
                destination = match.group(2)
                malicious_activities.append(
                    (f"Downloading from {url}", f"Destination: {destination}")
                )
            exploit_matches = re.finditer(r"(exploit|malware)", contents, re.IGNORECASE)
            for match in exploit_matches:
                malicious_activities.append(
                    (
                        match.group(0),
                        f"Exploit or malware reference at position {match.start()}",
                    )
                )
            encoded_matches = re.finditer(
                r'base64\.b(64)?decode\(\s*[\'"]([^\'"]+)[\'"]\s*\)', contents
            )
            for match in encoded_matches:
                malicious_activities.append(
                    (
                        match.group(0),
                        f"Encoded strings containing malicious content at position {match.start()}",
                    )
                )
            ip_port_matches = re.finditer(
                r"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b):(\d+)", contents
            )
            for match in ip_port_matches:
                ip_address = match.group(1)
                port = match.group(2)
                country = get_country_info(ip_address)
                if country:
                    malicious_activities.append(
    (
        f"IP address {ip_address}: Originating from {country}, connecting on port {port}" if country else f"IP address {ip_address}: Connecting on port {port}",
        "",
    )
)
                else:
                    malicious_activities.append(
                        (
                            f"IP address {ip_address}",
                            f"Country information not available, connecting on port {port}",
                        )
                    )
                # Check IP reputation on VirusTotal
                scan_ip_virustotal(ip_address)
                
            if malicious_activities:
                print(
                    f"{COLOR_RED}Malicious activity detected in {file_name}:{COLOR_RESET}"
                )
                for activity, details in malicious_activities:
                    print(f"{COLOR_YELLOW} - {activity}:{COLOR_RESET} {details}")
            else:
                print(
                    f"{COLOR_GREEN}No malicious activity detected in {file_name}{COLOR_RESET}"
                )
            file_size = os.path.getsize(file_path)
            print(f"{COLOR_CYAN}File size:{COLOR_RESET} {file_size} bytes")
            file_modified_time = os.path.getmtime(file_path)
            modified_time_formatted = time.strftime(
                "%m/%d/%Y %I:%M%p", time.localtime(file_modified_time)
            )
            print(
                f"{COLOR_CYAN}Last modified time:{COLOR_RESET} {modified_time_formatted}"
            )
            file_hash = calculate_file_hash(file_path)
            if file_hash:
                print(f"{COLOR_CYAN}File hash:{COLOR_RESET} {file_hash}")
                print(f"{COLOR_CYAN}Scanning file on VirusTotal...{COLOR_RESET}")
                result = scan_file_virustotal(file_hash)
                if result:
                    print(f"{COLOR_CYAN}VirusTotal scan results:{COLOR_RESET}")
                    for scan in result["data"]["attributes"][
                        "last_analysis_results"
                    ].items():
                        scan_result = scan[1]
                        scan_result_str = (
                            f"{scan_result['category']} - {scan_result['result']}"
                        )
                        if scan_result["category"] == "malicious":
                            print(
                                f"{COLOR_RED} - {scan[0]}:{COLOR_RESET} {scan_result_str}"
                            )
                        else:
                            print(
                                f"{COLOR_GREEN} - {scan[0]}:{COLOR_RESET} {scan_result_str}"
                            )
                else:
                    print(
                        f"{COLOR_YELLOW}No scan results available from VirusTotal.{COLOR_RESET}"
                    )
    except Exception as e:
        print(f"Error analyzing {file_name}: {e}")



def get_country_info(ip_address):
    try:
        print(f"Retrieving country information for IP address: {ip_address}")
        result = ipapi.location(ip_address)
        country = result['country_name']
        print(f"Country: {country}")
        print("Checking IP reputation on VirusTotal...")
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
            headers={"x-apikey": API_KEY},
        )
        if response.status_code == 200:
            vt_result = response.json()
            if vt_result["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
                print(
                    f"{COLOR_RED}VirusTotal indicates this IP has malicious activity{COLOR_RESET}"
                )
            else:
                print("VirusTotal indicates this IP does not have any known malicious activity.")
        else:
            print("Error checking IP reputation on VirusTotal.")
    except Exception as e:
        print(f"Error retrieving country information for {ip_address}: {e}")



def calculate_file_hash(file_path):
    try:
        with open(file_path, "rb") as file:
            file_hash = hashlib.md5()
            while chunk := file.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return None


def scan_file_virustotal(file_hash):
    try:
        url = f"https://www.virustotal.com/gui/search/{file_hash}"
        headers = {"x-apikey": API_KEY}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            if "data" in result and "id" in result["data"]:
                return result
            else:
                print(f"Error scanning file on VirusTotal: No scan results found")
                return None
        else:
            print(f"Error scanning file on VirusTotal: {response.status_code}")
            print(f"Response content: {response.content}")
            return None
    except Exception as e:
        print(f"Error scanning file on VirusTotal: {e}")
        return None


def extract_strings(file_path):
    try:
        print("\n\033[34m-------------------------------------------Quick String Analyzing:-------------------------------------------\033[0m\n")
        result = subprocess.run(["strings", file_path], capture_output=True, text=True)
        if result.returncode == 0:
            strings_output = result.stdout
            potential_harmful_strings = []

            harmful_patterns = [
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                r"(https?://[^\s]+)",
                r"[\w\.-]+\/[\w\.-]+",
                r"(pass(?:word)?|credit.*card|ssn|malware|exploit)",
                r"(\b(?:eval|exec|shell|system|os\.popen|subprocess\.Popen|wscript\.shell|cmd\.exe|powershell)\b)",
            ]

            for line in strings_output.splitlines():
                unique_strings_in_line = set()  # Create a set to store unique strings in this line
                for pattern in harmful_patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        matched_string = match.group()
                        unique_strings_in_line.add(matched_string)  # Add the matched string to the set

                # Detect and decode Base64-encoded strings
                base64_matches = re.finditer(r'(["\'])([A-Za-z0-9+/]+={0,2})\1', line)
                for match in base64_matches:
                    encoded_string = match.group(2)
                    function_call = ''
                    try:
                        decoded_string = base64.b64decode(encoded_string).decode('utf-8')
                        # Find the function call associated with the encoded string
                        function_call_match = re.search(fr'(["\']){encoded_string}\1\s*=\s*base64\.b64decode', line)
                        if function_call_match:
                            function_call = function_call_match.group()
                        print(f'encoded_data = "{encoded_string}" -> "{decoded_string}"')
                    except Exception as e:
                        # Unable to decode or invalid Base64 string
                        pass

                if unique_strings_in_line:
                    # Highlight and append the potential harmful strings
                    highlighted_line = line
                    for matched_string in unique_strings_in_line:
                        highlighted_line = highlighted_line.replace(matched_string, f"\033[93m{matched_string}\033[0m")
                    potential_harmful_strings.append(highlighted_line)

            if potential_harmful_strings:
                print("Potential dangerous strings:")
                for s in potential_harmful_strings:
                    # Extract IP address and get country information
                    ip_addresses = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s)
                    for ip_address in ip_addresses:
                        country = get_country_info(ip_address)
                        if country:
                            print(f"IP address {ip_address} originating from {country}")
                            break  # Move to the next string if IP information is found
                        else:
                            print(f"IP address {ip_address} (Country information not available)")
                    print(s)
                return potential_harmful_strings
            else:
                print("No potential harmful strings found.")
                return None
        else:
            print("Error extracting strings from the binary file.")
            return None
    except Exception as e:
        print(f"Error extracting strings: {e}")
        return None








def main():
    parser = argparse.ArgumentParser(
        description="File analysis tool for detecting malicious activity."
    )
    parser.add_argument("-f", "--file", type=str, help="File to analyze")
    args = parser.parse_args()
    if args.file:
        if args.file.endswith(".txt"):
            analyze_text(args.file)
        elif args.file.endswith(".py"):
            analyze_python(args.file)
        elif args.file.endswith(".exe"):
            analyze_exe(args.file)
        else:
            analyze_file(args.file)
    else:
        print("Please specify a file using the -f or --file option.")


if __name__ == "__main__":
    main()

