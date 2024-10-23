import os
import json

source_folder = 'ics-scada'  
destination_folder = 'ics-scada-cve'

if not os.path.exists(destination_folder):
    os.makedirs(destination_folder)

for filename in os.listdir(source_folder):
    if filename.endswith('.json'):
        file_path = os.path.join(source_folder, filename)
        
        with open(file_path, 'r') as file:
            data = json.load(file)
        
        results_with_vulns = []
        for entry in data:
            if entry["Vulnerabilities"] != "None":
                vulnerabilities = entry["Vulnerabilities"]
                for cve, details in vulnerabilities.items():
                    result = {
                        "IP": entry["IP"],
                        "Port": entry["Port"],
                        "CVE": cve,
                        "Summary": details["summary"]
                    }
                    results_with_vulns.append(result)
        
        output_file_path = os.path.join(destination_folder, f'{filename.split(".")[0]}_cve_results.json')
        with open(output_file_path, 'w') as output_file:
            json.dump(results_with_vulns, output_file, indent=4)

print("Results have been processed and saved to the 'ics-scada-cve' folder.")
