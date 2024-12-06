from bs4 import BeautifulSoup
import requests

url = "https://cloud.google.com/support/bulletins"

try:
    response = requests.get(url)
    response.raise_for_status()  
    soup = BeautifulSoup(response.text, 'html.parser')

    vulnerabilities = []

    for section in soup.find_all('h2'):
        vulnerability = {}
        
        vulnerability['title'] = section.get_text(strip=True)
        
        published = section.find_next('p')
        if('Published' in published.get_text(strip=True) and 'Updated' in published.get_text(strip=True)):
        
            published_text = published.get_text(strip=True)
            published = published_text.split('Published:')[1].split('Updated:')[0].strip() if 'Published:' in published_text else None
            
            # Extract 'Updated' date (if available)
            updated = published_text.split('Updated:')[1].strip() if 'Updated:' in published_text else 'N/A'

            vulnerability['published'] = published
            vulnerability['updated'] = updated

        else:
            if published:
                vulnerability['published'] = published.get_text(strip=True).replace('Published:', '').strip()
            else:
                vulnerability['published'] = None

            updated = published.find_next_sibling('p')
            if 'Published' in updated.get_text(strip=True):
                updated = None
            if updated:
                vulnerability['updated'] = updated.get_text(strip=True).replace('Updated:', '').strip()
            else:
                vulnerability['updated'] = 'N/A'  
        
        table = section.find_next('table')
        description_cell = table.find('td') if table else None
        if description_cell:
            vulnerability['description'] = description_cell.get_text(strip=True).strip()
        
        severity_cell = table.find_all('td')[1] if table else None
        vulnerability['severity'] = severity_cell.get_text(strip=True) if severity_cell else None
        
        cves = []
        notes_cell = table.find_all('td')[2] if table else None
        if notes_cell:
            for a_tag in notes_cell.find_all('a', href=True):
                if 'CVE' in a_tag.get_text(strip=True):
                    cves.append(a_tag.get_text(strip=True))
        vulnerability['cves'] = cves
        
        vulnerabilities.append(vulnerability)

except Exception as e:
    print("An error occurred while fetching the data", e)

for v in vulnerabilities:
    print(v)
