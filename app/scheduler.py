# app/scheduler.py

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from time import sleep
from threading import Thread

from .models import OEMWebsite

# Import the scraping function or any background task you want to schedule
from .scraping import scrape_task  # Modify this to your actual scraping task import
from .scrape.dynscr import dynamic_scraper

def start_scheduler():
    """
    Starts the APScheduler and schedules the scraping task every 60 minutes.
    """
    scheduler = BackgroundScheduler()

    oem_website = OEMWebsite.query.all()

    print(oem_website)

    # Add the job that will run every 60 minutes
    scheduler.add_job(
        func=dynamic_scraper,
        trigger=IntervalTrigger(seconds=10),
        id="scraping_job",  # Unique job ID
        name="Scraping Job",  # Optional name
        replace_existing=True  # Replace the job if it already exists
    )

    # Start the scheduler
    scheduler.start()

    # Keep the app running (scheduler will keep running in the background)
    while True:
        sleep(1)  # Let the scheduler keep running
