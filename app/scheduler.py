from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
from time import sleep
from threading import Thread
from flask import current_app
from app import create_app, db
from app.models import OEMWebsite
from app.scrape.dynscr import dynamic_scraper
from app.scrape.document import Document

def job_listener(event):
    """
    Listener for job events to capture the return value (a list).
    """
    if event.exception:
        print(f"Job {event.job_id} failed!")
    else:
        print(f"Job {event.job_id} completed successfully!")
        print(f"Job result (List): {event.retval}")  # Print the list returned by dynamic_scraper


def start_scheduler():
    """
    Starts the APScheduler and schedules the scraping task every 60 minutes.
    """
    # Create an instance of the app
    app = create_app()

    # Create a background scheduler instance
    scheduler = BackgroundScheduler()

    # Use the Flask application context to query the database
    with app.app_context():
        oem_website = OEMWebsite.query.all()
        print("OEM Websites:", oem_website)

    # Create documents based on the OEMWebsite data
    documents = []
    for website in oem_website:
        documents.append(Document(
            page_content="",
            metadata={"source": website.website_url, "contains_cve": False},
            contains_listing=website.contains_listing,
            contains_date=website.contains_date,
            contains_details=website.contains_details
        ))

    # Add a listener for job events (to capture results)
    scheduler.add_listener(job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)

    # Schedule the scraping task to run every 60 minutes
    scheduler.add_job(
        func=lambda: dynamic_scraper(documents),  # Properly wrap the function to pass documents
        trigger=IntervalTrigger(seconds=10),  # Use a shorter interval for testing
        id="scraping_job",  # Unique job ID
        name="Scraping Job",  # Optional name
        replace_existing=True  # Replace the job if it already exists
    )

    # Start the scheduler
    scheduler.start()

    print("Scheduler started.")

    # Function to keep the scheduler running in the background
    def keep_alive():
        while True:
            sleep(1)  # Let the scheduler keep running

    # Run the scheduler in a separate thread to avoid blocking the main thread
    scheduler_thread = Thread(target=keep_alive)
    scheduler_thread.daemon = True  # This allows the thread to exit when the main process exits
    scheduler_thread.start()
