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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker, scoped_session

# Set up logging
logging.basicConfig(level=logging.INFO)

def map_additional_details_to_vulnerability(additional_details: AdditionalDetails, oem_website_id: int) -> Vulnerabilities:
    """
    Maps AdditionalDetails to a Vulnerabilities model instance.
    """
    try:
        vulnerability = Vulnerabilities(
            unique_id=additional_details.CVE_ID,
            product_name_version=', '.join(additional_details.Affected_Products_with_Version) if additional_details.Affected_Products_with_Version else "N/A",
            vendor=additional_details.Vendor or "Unknown Vendor",
            severity_level=additional_details.Severity_Level or "Unknown",
            vulnerability=additional_details.Summary or "N/A",
            remediation=additional_details.Remediation or "N/A",
            impact=additional_details.Impact_or_Exploitation or "N/A",
            cvss_score=float(additional_details.CVSS_Base_Score) if additional_details.CVSS_Base_Score else None,
            reference=', '.join(additional_details.References) if additional_details.References else None,
            additional_details=additional_details.model_dump(by_alias=True),
            published_date=datetime.utcnow(),
            oem_website_id=oem_website_id,
        )
        return vulnerability
    except Exception as e:
        logging.error(f"Error while mapping AdditionalDetails to Vulnerabilities: {e}")
        raise


def job_listener(event, app: Flask):
    """
    Listener for job events to capture return values (list of results).
    """
    if event.exception:
        logging.error(f"Job {event.job_id} failed with exception: {event.exception}")
    else:
        logging.info(f"Job {event.job_id} completed successfully!")

        with app.app_context():
        # Create a scoped session for thread safety
            session_factory = sessionmaker(bind=db.engine)
            scoped_session_factory = scoped_session(session_factory)

            results = event.retval
            if not results or not isinstance(results, list):
                logging.warning("No valid results returned from the job.")
                return

            try:
                for info, website_id in results:
                    oem_website = scoped_session_factory.query(OEMWebsite).get(website_id)
                    if not oem_website:
                        logging.warning(f"No OEMWebsite found for ID: {website_id}")
                        continue

                    vulnerability = map_additional_details_to_vulnerability(info, oem_website.id)
                    scoped_session_factory.add(vulnerability)
                    scoped_session_factory.commit()
                    print("The END")
                    logging.info(f"Vulnerability for {oem_website.website_url} added successfully.")
            except IntegrityError as e:
                scoped_session_factory.rollback()
                logging.error(f"IntegrityError adding vulnerability for {oem_website.website_url}: {e} Rolled back.")
            except Exception as e:
                scoped_session_factory.rollback()
                logging.error(f"Error adding vulnerability for {oem_website.website_url}: {e}. Rolled back.")
            finally:
                scoped_session_factory.remove()


def start_scheduler():
    app = create_app()
    scheduler = BackgroundScheduler()

    with app.app_context():
        try:
            oem_websites = OEMWebsite.query.all()
            documents = [Document(page_content="", metadata={"source": website.website_url, "contains_cve": False, "id": website.id},
                                 contains_listing=website.contains_listing,
                                 contains_date=website.contains_date,
                                 is_rss = website.is_rss,
                                 contains_details=website.contains_details) for website in oem_websites]
        except Exception as e:
            logging.error(f"Error fetching OEM websites: {e}")
            return

    scheduler.add_listener(lambda event: job_listener(event, app), EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)

    scheduler.add_job(
        func=lambda: dynamic_scraper(app),
        trigger=IntervalTrigger(seconds=10),
        id="scraping_job",
        name="Scraping Job",
        replace_existing=True
    )

    scheduler.start()
    logging.info("Scheduler started successfully.")

    def keep_alive():
        try:
            while True:
                sleep(1)
        except KeyboardInterrupt:
            scheduler.shutdown()

    scheduler_thread = Thread(target=keep_alive)
    scheduler_thread.daemon = True
    scheduler_thread.start()

if __name__ == "__main__":
    start_scheduler()
