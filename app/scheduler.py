from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
from time import sleep
from threading import Thread
from flask import Flask
from app import create_app, db
from app.models import OEMWebsite, Vulnerabilities
from app.scrape.dynscr import dynamic_scraper
from app.scrape.document import Document
from app.scrape.vuln_details import AdditionalDetails
from datetime import datetime
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    filename='logs/scraping.log',  # Log file path
    level=logging.INFO,  # Capture INFO level and above (INFO, WARNING, ERROR)
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
)


def map_additional_details_to_vulnerability(additional_details: AdditionalDetails, oem_website_id: int) -> Vulnerabilities:
    """
    Maps AdditionalDetails to a Vulnerabilities model instance.
    """
    vulnerability = Vulnerabilities(
        unique_id=additional_details.CVE_ID,
        product_name_version=', '.join(additional_details.Affected_Products_with_Version) if additional_details.Affected_Products_with_Version else None,
        vendor=additional_details.Vendor or "Unknown Vendor",
        severity_level=additional_details.Severity_Level or "Unknown",
        vulnerability=additional_details.Summary or "N/A",
        remediation=additional_details.Remediation or "N/A",
        impact=additional_details.Impact_or_Exploitation or "N/A",
        cvss_score=float(additional_details.CVSS_Score) if additional_details.CVSS_Score else None,
        reference=', '.join(additional_details.References) if additional_details.References else None,
        additional_details=additional_details.model_dump(by_alias=True),
        published_date=datetime.utcnow(),  # Replace with the actual publication date if available
        oem_website_id=oem_website_id,
    )
    return vulnerability

def job_listener(event, app: Flask):
    """
    Listener for job events to capture return values (list of results).
    """
    if event.exception:
        print(f"Job {event.job_id} failed with exception: {event.exception}")
    else:
        print(f"Job {event.job_id} completed successfully!")
        results = event.retval
        if not results:
            print("No results returned from the job.")
            return
        
        with app.app_context():
            for info, website_url in results:
                print(website_url)
                oem_website = OEMWebsite.query.filter_by(website_url=website_url).first()
                print(oem_website)
                if oem_website:
                    try:
                        vulnerability = map_additional_details_to_vulnerability(info, oem_website.id)
                        db.session.add(vulnerability)
                        db.session.commit()
                        print(f"Vulnerability for {website_url} added successfully.")
                    except Exception as e:
                        print(f"Error adding vulnerability for {website_url}: {e}")
                        db.session.rollback()

def start_scheduler():
    """
    Starts the APScheduler and schedules the scraping task every 60 minutes.
    """
    app = create_app()
    scheduler = BackgroundScheduler()

    with app.app_context():
        try:
            oem_websites = OEMWebsite.query.all()
            print("OEM Websites fetched:", oem_websites)
        except Exception as e:
            print(f"Error fetching OEM websites: {e}")
            return

        documents = []
        for website in oem_websites:
            documents.append(Document(
                page_content="",
                metadata={"source": website.website_url, "contains_cve": False, "id": website.id},
                contains_listing=website.contains_listing,
                contains_date=website.contains_date,
                contains_details=website.contains_details
            ))

    # Add a listener for job events
    scheduler.add_listener(lambda event: job_listener(event, app), EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)

    # Schedule the scraping job
    scheduler.add_job(
        func=lambda: dynamic_scraper(documents),  # Ensure dynamic_scraper processes the documents correctly
        trigger=IntervalTrigger(seconds=30),  # Set to 60 minutes for production
        id="scraping_job",
        name="Scraping Job",
        replace_existing=True
    )

    # Start the scheduler
    scheduler.start()
    print("Scheduler started successfully.")

    # Keep the scheduler alive in a separate thread
    def keep_alive():
        try:
            while True:
                sleep(1)
        except KeyboardInterrupt:
            scheduler.shutdown()

    # Run the scheduler in a separate thread
    scheduler_thread = Thread(target=keep_alive)
    scheduler_thread.daemon = True
    scheduler_thread.start()
