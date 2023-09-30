import requests
import pandas as pd

# Base URL for retrieving CVE information
url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

# Your API key
api_key = 'API-KEY'  # Replace with your actual API key

# Take vendor, package name, and version as user input
vendor = input("Enter the vendor name: ")
package = input("Enter the package name: ")
version = input("Enter the version: ")

# Construct the CPE name
cpe_name = f"cpe:2.3:a:{vendor}:{package}:{version}:*:*:*:*:*:*:*"

# Headers for the GET request
headers = {
    'apiKey': api_key
}

# Initialize a list to store all vulnerabilities
all_vulnerabilities = []

# Initial values for pagination
start_index = 0
results_per_page = 100  # Adjust this value based on how many results you want to fetch per request

while True:
    # Parameters for the GET request
    params = {
        'cpeName': cpe_name,
        'resultsPerPage': results_per_page,
        'startIndex': start_index
    }

    # Send a GET request to the NVD API
    response = requests.get(url, headers=headers, params=params)
    print(response.text) # This is to check if the API loaded values

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the JSON response
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])  # Use 'vulnerabilities' key instead of 'result'

        # Break the loop if no more vulnerabilities
        if not vulnerabilities:
            break

        # Extract the relevant information from the vulnerabilities
        for item in vulnerabilities:
            cve_data = item.get('cve', {})
            cve = cve_data.get('id', 'N/A')
            description_data = cve_data.get('descriptions', [{}])
            description = description_data[0].get('value', 'N/A') if description_data else 'N/A'
            published_date = cve_data.get('published', 'N/A')
            last_modified = cve_data.get('lastModified', 'N/A')
            metrics_data = cve_data.get('metrics', {})
            cvss_metric_v31 = metrics_data.get('cvssMetricV31', [{}])
            cvssv3_data = cvss_metric_v31[0].get('cvssData', {}) if cvss_metric_v31 else {}
            cvssv3_score = cvssv3_data.get('baseScore', 'N/A')
            severity = cvssv3_data.get('baseSeverity', 'N/A')

            all_vulnerabilities.append({
                'CVE': cve,
                'Description': description,
                'CVSSv3 Score': cvssv3_score,
                'Severity': severity,
                'Published Date': published_date,
                'Last Modified': last_modified

            })

        # Increment the start index for pagination
        start_index += results_per_page
    else:
        print(f"Error fetching data from NVD API: HTTP Status Code {response.status_code}")
        break

# Write the results to an Excel file
df = pd.DataFrame(all_vulnerabilities)
output_filename = f"{vendor}_{package}_{version}_vulnerabilities.xlsx"
df.to_excel(output_filename, index=False)

print(f"Vulnerabilities have been written to {output_filename}")
