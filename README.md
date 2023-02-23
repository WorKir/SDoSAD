# Slow DDoS Attack Detector
Detection a slow DDoS attacks in DataFlow traffic dumps

## Description
This document was created to describe the use of the "Slow DDoS Attack Detector" program (hereinafter - the Program). The program makes it possible to determine from which IP addresses a slow denial of service attack occurred by analyzing TCP flows.
When the program starts, the file specified for it is opened and processed according to the specified criteria. The program works in two modes:
1. Normal traffic analysis mode: accepts only a file with TCP streams of normal traffic, analyzes them and creates a limits.csv file with limit values for the given network.
2. Attack detection mode: accepts a file with TCP streams to be investigated and a limis.csv file with limit values generated for a given network.

After running the program, you can see the following information on the screen:
* Limit values for the network if the program was run in analysis mode.
* Malicious addresses from which the attack was carried out, if the program was launched in detection mode.
 
The program is presented in the form of a SDoSAD.py file.
The structure of the directory with the necessary files for working with the program:
* SDoSAD.py
* requirements.txt – a list of libraries used by the program

Prerequisites for starting work with the program:
* Install the Python environment from the official website version greater than or equal to 3.9.13 URL: https://www.python.org/
* Install the “pip” package manager for Python.
* For the test, you can download test sets of traffic in the form of TCP streams in a file with the extension .csv.
* If you only have a .pcap traffic file, you can convert it to a corresponding TCP flow .csv file using the CICFlowMeter tool. More about CICFlowMeter
you can find out at the link. URL: https://github.com/ahlashkari/CICFlowMeter

Remark! For the correct operation of the program, it is necessary that the file with TCP streams in csv format has correct circles in the header. If their field names in the header of your file differ from the headers in the header.txt file, you must manually replace them.

Steps to start the program:
1. Open the command line and go to the directory with the program files.
2. Installation of the necessary packages used by the program: 
```bash
python -m pip3 install -r requirements.txt
```
3. Running the program with the appropriate path to the files in normal traffic analysis mode:
```bash
python3 SDoSAD.py -b <file.csv>
```
4. Launch the program with the appropriate path to the files in the mode
detection of malicious addresses:
```bash
python3 SDoSAD.py -f <file.csv> -l <limits.csv>
```
5. You can also use the [-i] or [--info] flag to display additional information on the addresses found:
```bash
python3 SDoSAD.py -f <file.csv> -l <limits.csv> -info
```

## Test dataset
The Datasets.zip archive contains files with datasets on which the program was tested. It includes normal traffic and normal+malicious
