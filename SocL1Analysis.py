import os
import json
from pathlib import Path
import google.generativeai as genai

# Configure the Gemini API with the API key from environment variable
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))


model = genai.GenerativeModel('gemini-1.5-flash')


DEFAULT_FILE_PATH = r"Detection-2.json"  #jason file exported from SIEM/EDR 

def load_json_file(file_path):
    """Load and validate JSON file."""
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {str(e)}")
    except Exception as e:
        raise Exception(f"Error loading file: {str(e)}")

def summarize_detections(data):
    """Summarize all EDR detection data for Gemini AI prompt."""
    try:
        if not isinstance(data, list) or not data:
            return "No detection data found in JSON file."
        
        summary = []
        for i, detection in enumerate(data):
          
            device = detection.get('device', {})
            hostname = device.get('hostname', 'Unknown')
            device_id = device.get('device_id', 'Unknown')
            os_version = device.get('os_version', 'Unknown')
            local_ip = device.get('local_ip', 'Unknown')
            external_ip = device.get('external_ip', 'Unknown')
            
            
            severity = detection.get('severity_name', 'Unknown')
            detection_name = detection.get('display_name', detection.get('description', 'Unknown'))
            tactic = detection.get('tactic', 'Unknown')
            technique = detection.get('technique', 'Unknown')
            timestamp = detection.get('context_timestamp', detection.get('timestamp', 'Unknown'))
            
           
            filename = detection.get('filename', 'Unknown')
            filepath = detection.get('filepath', 'Unknown')
            sha256 = detection.get('sha256', 'Unknown')
            cmdline = detection.get('cmdline', 'Unknown')[:100] + '...' if len(detection.get('cmdline', '')) > 100 else detection.get('cmdline', 'Unknown')
            user = detection.get('user_name', 'Unknown')
            
            
            parent = detection.get('parent_details', {})
            parent_filename = parent.get('filename', 'Unknown')
            parent_cmdline = parent.get('cmdline', 'Unknown')[:100] + '...' if len(parent.get('cmdline', '')) > 100 else parent.get('cmdline', 'Unknown')
            parent_user = 'Unknown'
            grandparent = detection.get('grandparent_details', {})
            grandparent_filename = grandparent.get('filename', 'Unknown')
            grandparent_cmdline = grandparent.get('cmdline', 'Unknown')[:100] + '...' if len(grandparent.get('cmdline', '')) > 100 else grandparent.get('cmdline', 'Unknown')
            grandparent_user = 'Unknown'
            
           
            ioc_context = detection.get('ioc_context', [])
            iocs = [f"Type: {ioc.get('ioc_type', 'Unknown')}, Value: {ioc.get('ioc_value', 'Unknown')}, Source: {ioc.get('ioc_source', 'Unknown')}" 
                    for ioc in ioc_context]
            ioc_summary = "\n    - " + "\n    - ".join(iocs) if iocs else "None"
            
          
            network_accesses = detection.get('network_accesses', [])
            network_summary = []
            for net in network_accesses[:3]:
                net_info = (f"Protocol: {net.get('protocol', 'Unknown')}, "
                           f"Local: {net.get('local_address', 'Unknown')}:{net.get('local_port', 'Unknown')}, "
                           f"Remote: {net.get('remote_address', 'Unknown')}:{net.get('remote_port', 'Unknown')}, "
                           f"Direction: {net.get('connection_direction', 'Unknown')}")
                network_summary.append(net_info)
            network_summary = "\n    - " + "\n    - ".join(network_summary) if network_summary else "None"
            
            
            disposition = detection.get('pattern_disposition_description', 'Unknown')
            disposition_details = detection.get('pattern_disposition_details', {})
            process_blocked = 'Yes' if disposition_details.get('kill_process', False) or disposition_details.get('operation_blocked', False) else 'No'
            quarantine_file = 'Yes' if disposition_details.get('quarantine_file', False) else 'No'
            
            summary.append(
                f"Detection {i+1}:\n"
                f"  Device:\n"
                f"    Hostname: {hostname}\n"
                f"    Device ID: {device_id}\n"
                f"    OS Version: {os_version}\n"
                f"    Local IP: {local_ip}\n"
                f"    External IP: {external_ip}\n"
                f"  Event Details:\n"
                f"    Severity: {severity}\n"
                f"    Detection Name: {detection_name}\n"
                f"    Tactic: {tactic}\n"
                f"    Technique: {technique}\n"
                f"    Timestamp: {timestamp}\n"
                f"  Suspect File/Process:\n"
                f"    Filename: {filename}\n"
                f"    Filepath: {filepath}\n"
                f"    SHA256: {sha256}\n"
                f"    CMDline: {cmdline}\n"
                f"    User: {user}\n"
                f"  Parent Process:\n"
                f"    Filename: {parent_filename}\n"
                f"    CMDline: {parent_cmdline}\n"
                f"    User: {parent_user}\n"
                f"  Grandparent Process:\n"
                f"    Filename: {grandparent_filename}\n"
                f"    CMDline: {grandparent_cmdline}\n"
                f"    User: {grandparent_user}\n"
                f"  Disposition: {disposition}\n"
                f"  Remediation Actions:\n"
                f"    Process Blocked: {process_blocked}\n"
                f"    Quarantine File: {quarantine_file}\n"
                f"  IOCs:\n    - {ioc_summary}\n"
                f"  Network Accesses:\n    - {network_summary}\n"
            )
        
        return "\n".join(summary)
    except Exception as e:
        return f"Error summarizing data: {str(e)}"

def get_gemini_analysis(data_summary):
    """Send summarized data to Gemini AI for analysis with chunking."""
    try:
       
        base_prompt = (
            "You are a cybersecurity expert analyzing Security Operation Center data from SIEM. "
            "I have submitted detections, and I want you to thoroughly examine and analyze each detection like a Security Operations Center (SOC). "
            "For each and every detection, provide the following information:\n\n"
            "**Executive Summary**: Briefly describe the event and its outcome.\n\n"
            "**Event Details**:\n"
            "  - Severity: \n"
            "  - Detection Name: \n"
            "  - Tactic: \n"
            "  - Technique: \n"
            "  - Timestamp: \n\n"
            "**Involved Entities**:\n"
            "  - Device:\n"
            "      - Hostname: \n"
            "      - Device ID: \n"
            "      - OS Version: \n"
            "      - Local IP: \n"
            "      - External IP: \n"
            "  - Suspect File/Process:\n"
            "      - Filename: \n"
            "      - Filepath: \n"
            "      - SHA256: \n"
            "      - CMDline: \n"
            "      - User: \n"
            "  - Parent Process:\n"
            "      - Filename: \n"
            "      - CMDline: \n"
            "      - User: \n"
            "  - Grandparent Process:\n"
            "      - Filename: \n"
            "      - CMDline: \n"
            "      - User: \n\n"
            "**Analysis**: Explain what happened, why it was detected, and the potential implications if the threat hadn't been stopped.\n\n"
            "**Remediation Actions Taken**:\n"
            "  - Process Blocked: \n"
            "  - Quarantine File: \n\n"
            "**Recommendations**: Suggest further actions for a SOC analyst, including user education and any follow-up monitoring.\n\n"
            "Provide your analysis in a clear, structured format with headings for each detection and the requested sections.\n\n"
        )
        
        
        CHUNK_SIZE = 100000
        chunks = [data_summary[i:i+CHUNK_SIZE] for i in range(0, len(data_summary), CHUNK_SIZE)]
        responses = []
        
        for i, chunk in enumerate(chunks):
            prompt = f"{base_prompt}Data Summary (Chunk {i+1}):\n{chunk}\n\nAnalyze all detections in this chunk."
            response = model.generate_content(prompt)
            responses.append(response.text)
        
        # Combine responses
        return "\n\n".join(responses)
    except Exception as e:
        return f"Error getting Gemini AI analysis: {str(e)}"

def main():
    """Main function to process JSON file and get Gemini AI analysis."""
    print("Detection Analysis Script")
    print(f"Default file path: {DEFAULT_FILE_PATH}")
    print("Press Enter to use the default file, enter a different file path, or type 'exit' to quit:")
    
    while True:
        user_input = input("> ").strip()
        if user_input.lower() == 'exit':
            print("Exiting...")
            break
        
        file_path = DEFAULT_FILE_PATH if not user_input else user_input
        
        try:
            print(f"Loading file: {file_path}")
            data = load_json_file(file_path)
            
            print("Summarizing detection data...")
            data_summary = summarize_detections(data)
            
            print("Sending data to Gemini AI for analysis...")
            analysis = get_gemini_analysis(data_summary)
            
            print("\nGemini AI Analysis:")
            print("-" * 80)
            print(analysis)
            print("-" * 80)
            print("\nPress Enter to use the default file, enter another file path, or type 'exit' to quit:")
        
        except Exception as e:
            print(f"Error: {str(e)}")
            print("Press Enter to use the default file, enter another file path, or type 'exit' to quit:")

if __name__ == "__main__":
    main()