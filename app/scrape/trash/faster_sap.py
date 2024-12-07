from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

driver = webdriver.Chrome()

import requests
from bs4 import BeautifulSoup
import re

url = "https://support.sap.com/en/my-support/knowledge-base/security-notes-news/november-2024.html"

try:
    response = requests.get(url)
    response.raise_for_status()  
    soup = BeautifulSoup(response.text, 'html.parser')

    advisories = []
    rows = soup.find_all('tr')[1:]

    for row in rows:
        details = ''
        severity = ''
        cve = ''

        product = row.find_all('td')
        
        if product:
            severity = product[2].get_text(strip=True) if len(product) > 2 else "N/A"

           
            link_elements = row.find_all('a')
            if len(link_elements) >= 2:
                details = link_elements[1]['href'].strip()
            else:
                details = 'N/A'

            
            for item in product:
                match = re.search(r'\[(CVE-\d{4}-\d{4,7})\]', item.get_text())
                if match:
                    cve = match.group(1)
                    break
        else:
            continue

        advisories.append({
            "severity": severity,
            "cveNumber": cve,
            "details": details,
        })
    print(advisories)
    visited = []
    fetched = {}
    for vuln in advisories:
        if vuln['details'] in visited:
            dictionary = fetched[vuln['cveNumber']]
        else:
            if vuln['details'] == 'N/A':
                continue
            else:
                driver.get(vuln["details"]) 
            try:
                fields = WebDriverWait(driver, 10).until(
                    EC.presence_of_all_elements_located((By.XPATH, '//div[@class="mb-2"]'))
                )
            except:
                print(f"Error: Unable to locate fields on {vuln['details']}")
                continue
            keys = []
            values = []
            

            
            keys.append("date_published")
            keys.append("last_updated")
            keys.append("cvss_score")
            keys.append("summary")  
             
            try:
                value = driver.find_elements(By.CSS_SELECTOR, 'div#cve-cna-container-start time')
                published_time = value[0].text if len(value) > 0 else "N/A"
                updated_time = value[1].text if len(value) > 1 else "N/A"

            except:
                value = ["N/A", "N/A"] 
            values.append(published_time)
            values.append(updated_time)
            
            try:
                value = driver.find_element(By.CSS_SELECTOR, 'table td').get_attribute('textContent')
            except:
                value = "N/A"
            
            values.append(value.strip())

            try:
                value = driver.find_element(By.XPATH, "//p[contains(text(), 'Product')]/following-sibling::p")
                product_name = value.text if value else "N/A"

            except:
                product_name = "N/A"
            values.append(product_name.strip())

            try:
                value = driver.find_element(By.XPATH, "//h4[contains(text(), 'Description')]/following-sibling::p")
                description = value.text if value else "N/A"
            except:
                description = "N/A"
            values.append(description.strip())
            
            dictionary = dict(zip(keys, values))

            fetched[vuln['cveNumber']] = dictionary

            visited.append(vuln['details'])
            
        vuln["full_details"] = dictionary
    print(advisories)

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    driver.quit()
