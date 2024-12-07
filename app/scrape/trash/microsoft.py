from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
from datetime import date
today = date.today()
formatted_date = today.strftime("%b %d, %Y")
formatted_date = "Nov 12, 2024"
driver = webdriver.Chrome()
url = "https://msrc.microsoft.com/update-guide/"

try:
    driver.get(url) 
    severity_button = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.XPATH, '//*[@id="objectObject"]/div/div[2]/div/div[2]/div[3]/div/div/button[2]'  ))
    )
    
    severity_button.click()

    ul = WebDriverWait(driver, 10).until(
        EC.text_to_be_present_in_element((By.CLASS_NAME, 'ms-ContextualMenu-list'), 'Critical')
    )
    
    button = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.CSS_SELECTOR, 'ul li button[aria-posinset="1"]'))
    )

    button.click()
    severity_button.click()

    detail_fields = WebDriverWait(driver, 10).until(
        EC.presence_of_all_elements_located((By.CLASS_NAME, 'ms-DetailsRow-fields'))
    )
    fields = []
    for field in detail_fields:
        
        field_text = field.get_attribute("textContent")
        if formatted_date in field_text:
            fields.append(field)

    vulnerabilites = []
    for field in fields:
        product = field.find_element(By.CSS_SELECTOR, '[data-automation-key="product"]').get_attribute("textContent")
        severity = field.find_element(By.CSS_SELECTOR, '[data-automation-key="severity"]').get_attribute("textContent")
        impact = field.find_element(By.CSS_SELECTOR, '[data-automation-key="impact"]').get_attribute("textContent")
        fixedBuildNumber = field.find_element(By.CSS_SELECTOR, '[data-automation-key="fixedBuildNumber"]').get_attribute("textContent")
        article_links = [a.get_attribute('href') for a in field.find_elements(By.CSS_SELECTOR, '[data-automation-key="kbArticles"] ul li a')]
        download_links = [a.get_attribute('href') for a in field.find_elements(By.CSS_SELECTOR, '[data-automation-key="download"] ul li a')]
        details = field.find_element(By.CSS_SELECTOR, '[data-automation-key="cveNumber"] a').get_attribute('href')
        cveNumber = field.find_element(By.CSS_SELECTOR, '[data-automation-key="cveNumber"]').get_attribute("textContent")
        vulnerabilites.append({"product": product, "severity": severity, "impact": impact, "fixedBuildNumber": fixedBuildNumber, "article_links": article_links, "download_links": download_links, "details": details, "cveNumber": cveNumber})
    
    visited = []
    fetched = {}
    for vuln in vulnerabilites:
        if vuln['details'] in visited:
            dictionary = fetched[vuln['cveNumber']]
        else:
            driver.get(vuln["details"])
            fields = WebDriverWait(driver, 10).until(
                EC.presence_of_all_elements_located((By.CLASS_NAME, 'ms-DetailsRow-fields'))
            )
            keys = [k.find_element(By.TAG_NAME, 'details').find_element(By.TAG_NAME, 'summary').get_attribute('textContent') for k in driver.find_elements(By.CSS_SELECTOR, 'div[data-automation-key="metric"]')]
            values = [v.find_element(By.TAG_NAME, 'details').find_element(By.TAG_NAME, 'summary').get_attribute('textContent') for v in driver.find_elements(By.CSS_SELECTOR, 'div[data-automation-key="value"]')]
            dictionary = dict(zip(keys, values))
            fetched[vuln['cveNumber']] = dictionary
            visited.append(vuln['details'])
        vuln["full_details"] = dictionary
    print(vulnerabilites)
    time.sleep(15)
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    driver.quit()
