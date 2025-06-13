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
