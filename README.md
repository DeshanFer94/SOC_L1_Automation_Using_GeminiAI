# SOC_L1_Automation_Using_GeminiAI

This repository contains a Python script that automates the analysis of EEDR/SIEM data in JSON format for Security Operation Center (SOC) Level 1 analysts. The script extracts key details from EDR detections, summarizes them, and leverages Google Gemini AI to provide structured insights, including executive summaries, event details, analysis, remediation actions, and recommendations.

## Features

Comprehensive EDR Processing: Parses all detections in a JSON file, handling device info, process details, IOCs, and network accesses.
Gemini AI Integration: Uses Google Gemini 1.5 Flash for in-depth analysis, producing structured reports with executive summaries, event details, and recommendations.
Chunking for Large Datasets: Splits large summaries into chunks to stay within Gemini AI token limits, ensuring all detections are analyzed.
Customizable Input: Supports default or user-specified JSON file paths.
Structured Output: Generates clear reports with sections for analysis, remediation, and recommendations.
Error Handling: Robust validation for JSON files, API connectivity, and data processing.
Extensible: Adaptable for various EDR JSON formats or alternative AI models with minor modifications.

## Prerequisites

Python: Version 3.8 or higher.
Google Gemini API Key: Obtain from Google Cloud Console.
EDR JSON File: A valid JSON file containing EDR detections (e.g., Detection-2.json).
Operating System: Windows, macOS, or Linux.
Dependencies:
google-generativeai: For Gemini AI integration.
Standard Python libraries (os, json, pathlib).

## Installation

Clone the Repository:
>git clone https://github.com/your-username/soc-l1-analysis-automation.git

>cd soc-l1-analysis-automation

## Install Dependencies

>pip install google-generativeai

## Configure the Gemini API Key

Set the GOOGLE_API_KEY environment variable:
>export GOOGLE_API_KEY='your-api-key-here'  # On Windows: set GOOGLE_API_KEY=your-api-key-here

## Prepare EDR JSON File

Place your EDR JSON file (e.g., Detection.json) in the project directory or specify its path.
The default path is D:\User\AIProject\Detection.json (update in the script if needed).

## Usage

### Run the Script

>python edr_json_gemini_analysis.py

### Script Workflow

- Loads and validates the JSON file.
- Summarizes all detections (device, event, process, IOCs, network accesses).
- Sends summarized data to Gemini AI in chunks if needed.
- Outputs a detailed analysis to the console.

## Configuration

Default JSON Path: Modify DEFAULT_FILE_PATH in the script to change the default JSON file location:

>DEFAULT_FILE_PATH = r"path\to\your\detection.json"

Gemini Model: Defaults to gemini-1.5-flash. To use another model (e.g., gemini-1.5-pro):

>model = genai.GenerativeModel('gemini-1.5-pro')

Chunk Size: Adjust CHUNK_SIZE (default: 100,000 characters) for Gemini API requests:

>CHUNK_SIZE = 100000

API Key: Ensure GOOGLE_API_KEY is set securely via environment variables.

## Example Output

Below is a sample output for one detection from Detection.json

>'Security Operation Center L1 Analysis Automation Script
Default file path: D:\User\Detection.json
Press Enter to use the default file, enter a different file path, or type 'exit' to quit:
Loading file: D:\User\Detection.json
Summarizing detection data...
Sending data to Gemini AI for analysis...
>
>Gemini AI Analysis:
--------------------------------------------------------------------------------'
>
>## Detection 1 Analysis
>
>**Executive Summary**
>A suspicious macro in an Office document was detected on XX-XX-XX and flagged as potential malware. No preventative action was taken.
>
>**Event Details**:
>- Severity: High
>- Detection Name: CloudDetect-OnWriteMacroKestrelXMLHigh
> - Tactic: Machine Learning
> - Technique: Cloud-based ML
> - Timestamp: 2025-06-13T07:26:42Z
> -
> - **Involved Entities**:
> - Device:
> - Hostname: XX-XX-XX
> - Device ID: 60b898a9af1b43b0a46700a1396f320d
> - OS Version: Windows 11
> - Local IP: 172.20.1.1
> - External IP: xx.xx.xx.xx
> - Suspect File/Process:
> - Filename: WINWORD.EXE
> - Filepath: \Device\HarddiskVolume3\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
> - SHA256: 939d96d5548464e996b6d3a9b558a6f646d0f2dd5538935039b0a2271ce9a543
> - CMDline: "C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" /n /f "D:\Users\Desktop\Doc1.dot"
> - User: userxxx
> - Parent Process:
> - Filename: explorer.exe
> - CMDline: C:\WINDOWS\Explorer.EXE
> - User: Unknown
> - Grandparent Process:
> - Filename: userinit.exe
> - CMDline: C:\Windows\system32\userinit.exe
> - User: Unknown
> -
> - **Analysis**:
> - WINWORD.EXE wrote a macro to `Doc1.dot`, flagged by ML as malicious. This could indicate a malware attempt to persist or execute code. If unmitigated, it might have led to data theft or system compromise.
> -
> - **Remediation Actions Taken**:
> - Process Blocked: No
> - Quarantine File: No
> -
> - **Recommendations**
>   - Investigate `Doc1.dot` for malicious macros.
>   - Educate user `` on safe document handling.
>   - Monitor XX-XX-XX for further macro activity.'

## Troubleshooting

File Not Found:
- Ensure the JSON file exists at the specified path.
- Update DEFAULT_FILE_PATH if needed.

Invalid JSON:
- Validate the JSON file using a tool like jq or an online JSON validator.
- Fix syntax errors (e.g., missing commas, brackets).

API Key Error:
- Verify GOOGLE_API_KEY is set correctly.
- Check Gemini API quota and permissions in Google Cloud Console.

Too Few Detections:
- Confirm the JSON file contains the expected number of detections.
- Check for errors in the console output.

Gemini API Errors:
- Ensure stable internet connectivity.
- Verify the Gemini model (gemini-1.5-flash) is accessible in your region.


