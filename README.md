![mugetsuuu cover](https://github.com/nijiinhell/Mugetsu/assets/82414193/fa8b0471-4442-4daf-aa41-d886f7c5899b)

It's still under development: goals are adding some functions to make it more advanced and light-weight. Beside other analyze tools, it contains different kind of files to analyze such as .exe, .py, .txt etc.
I'm trying to add analyze function for other kind of f.types (js | pdf | xls(x) | dll etc.), deep but understandable analyze, integrate to other free services such as VirusTotal, CTI & Malware-based which everyone can use easily.
If you have wishes to implement, don't hesitate :)

Mugetsu - performs several key functions:

1. **File Type Analysis**: It identifies the type of file being analyzed (Python script, executable, or text file) based on the file extension.

2. **Metadata Extraction**: It retrieves metadata such as file size and creation time, providing insights into the file's attributes.

3. **File Hash Calculation**: It calculates the SHA-256 hash of the file, enabling further analysis and comparison.

4. **VirusTotal Integration**: It interacts with the VirusTotal API to analyze file hashes, retrieving scan results and identifying potential malicious activity.

5. **Packer and Obfuscation Detection**: It examines executable files for common packers and obfuscation techniques, detecting suspicious features that may indicate malicious intent.

6. **String Extraction and Analysis**: It extracts strings from binary files and analyzes them for potential indicators of malicious activity, such as suspicious URLs or encoded data.

7. **Color-Coded Output**: It provides color-coded output to highlight important information and potential threats, enhancing readability and interpretation of analysis results.

8. **Command-Line Interface (CLI)**: It offers a command-line interface for user interaction, allowing users to specify the file to analyze and providing a seamless experience.

These functionalities collectively enable the script to analyze files for malicious activity, detect potential threats, and provide valuable insights to aid in cybersecurity efforts.

Using: 
python mugetsu.py -f filename

Installation:
git clone https://github.com/nijiinhell/mugetsu ; cd mugetsu/

Note: Don't forget to put your VirusTotal API Key and install uninstalled libraries like "pip install [library name]" then enjoy :)
