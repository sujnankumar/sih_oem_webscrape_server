from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

driver = webdriver.Chrome()

url = "https://sec.cloudapps.cisco.com/security/center/publicationListing.x?product=Cisco&impact=critical&sort=-day_sir#~Vulnerabilities"

try:
    driver.get(url)
    rows = WebDriverWait(driver, 10).until(
        EC.presence_of_all_elements_located((By.XPATH, '//tr[contains(@ng-click, "toggleDetail")]'))
    )

    advisories = []
    for row in rows:
        product = row.find_element(By.CSS_SELECTOR, '.advListItem a').get_attribute('textContent')

        severity = row.find_element(By.CSS_SELECTOR, '.impactTD span.ng-binding').get_attribute('textContent')

        impact = severity  

        fixedBuildNumber = row.find_element(By.CSS_SELECTOR, '[width="10%"] span.ng-binding').get_attribute('textContent')

        article_links = [row.find_element(By.CSS_SELECTOR, '.advListItem a').get_attribute('href')]

        download_links = []

        details = row.find_element(By.CSS_SELECTOR, '.advListItem a').get_attribute('href')

        cveNumber = row.find_element(By.CSS_SELECTOR, '[width="15%"] p span.ng-binding').get_attribute('textContent')

        publication_date = row.find_element(By.XPATH, './td[4]/span').get_attribute('textContent')

        advisories.append({
            "product": product,
            "severity": severity,
            "impact": impact,
            "fixedBuildNumber": fixedBuildNumber,
            "article_links": article_links,
            "download_links": download_links,
            "details": details,
            "cveNumber": cveNumber,
            "publication_date": publication_date,
        })

    visited = []
    fetched = {}
    for vuln in advisories:
        if vuln['details'] in visited:
            dictionary = fetched[vuln['cveNumber']]
        else:
            driver.get(vuln["details"])
            fields = WebDriverWait(driver, 10).until(
                EC.presence_of_all_elements_located((By.XPATH, '//div[@class="mainContent"]'))
            )
            keys = []
            values = []

            
            keys.append("date_published")
            keys.append("last_updated")
            keys.append("cvss_score")
            keys.append("summary")  
             
            try:
                value = driver.find_element(By.CSS_SELECTOR, 'div.flexcol div#ud-published div.divLabelContent').get_attribute('textContent')
            except:
                value = "N/A"
            values.append(value)
            
            try:
                value = driver.find_element(By.CSS_SELECTOR, 'div.flexcol div#ud-last-updated div.divLabelContent').get_attribute('textContent')
            except:
                value = "N/A"
            values.append(value)

            try:
                value = driver.find_element(By.CSS_SELECTOR, 'div.flexcol div.ud-CVSSScore div.divLabelContent a[target="new"]').get_attribute('textContent')
            except:
                value = "N/A"
            values.append(value.strip())

            try:
                value = driver.find_element(By.CSS_SELECTOR, 'div.flexcol div#summaryfield p').get_attribute('textContent')
            except:
                value = "N/A"
            values.append(value)
            
            dictionary = dict(zip(keys, values))

            fetched[vuln['cveNumber']] = dictionary

            visited.append(vuln['details'])
            
        vuln["full_details"] = dictionary
    print(advisories)

except Exception as e:
    print(f"An error occurred: {e}")
finally:
    driver.quit()
