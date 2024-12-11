from .models import ScrapingLogs, OEMWebsite
from . import db
from datetime import datetime
import pytz
import logging
from sqlalchemy.orm import scoped_session, sessionmaker

ist = pytz.timezone('Asia/Kolkata')

logging.basicConfig(
    filename='logs/scraping.log',  # Log file path
    level=logging.INFO,  # Capture INFO level and above (INFO, WARNING, ERROR)
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
)

def log_scraping_start(app, url, logging):
    with app.app_context():
        # Create scoped session for thread safety
        session_factory = sessionmaker(bind=db.engine)
        scoped_session_factory = scoped_session(session_factory)

        try:
            # Try to get the existing log entry
            log = scoped_session_factory.query(ScrapingLogs).filter_by(website_url=url).first()

            if log:
                log.status = "started"
                scoped_session_factory.commit()  # Commit in scoped session
                logging.info("\"%s\",Started,%s", url, datetime.now().strftime("%H:%M:%S"))
            else:
                # If no log found, create a new log entry
                scraped_at = datetime.now(ist)
                website = scoped_session_factory.query(OEMWebsite).filter_by(website_url=url).first()
                if website:
                    log = ScrapingLogs(website_url=url, status="started", website_id=website.id, scraped_at=scraped_at)
                    scoped_session_factory.add(log)
                    scoped_session_factory.commit()
                    logging.info("\"%s\",Started,%s", url, datetime.now().strftime("%H:%M:%S"))
                else:
                    logging.warning(f"OEMWebsite not found for URL: {url}")
        except Exception as e:
            print(f"An error occurred while logging start for {url}: {e}")
            scoped_session_factory.rollback()  # Rollback on error
        finally:
            scoped_session_factory.remove()  # Clean up session

def log_scraping_end(app, url, logging):
    with app.app_context():
        # Create scoped session for thread safety
        session_factory = sessionmaker(bind=db.engine)
        scoped_session_factory = scoped_session(session_factory)

        try:
            # Get the existing log entry
            log = scoped_session_factory.query(ScrapingLogs).filter_by(website_url=url).first()

            if log:
                log.status = "completed"
                log.scraped_at = datetime.now(ist)
                scoped_session_factory.commit()  # Commit in scoped session
                logging.info("\"%s\",Completed,%s", url, datetime.now().strftime("%H:%M:%S"))
            else:
                logging.warning(f"No log found for URL: {url}")
        except Exception as e:
            print(f"An error occurred while logging end for {url}: {e}")
            scoped_session_factory.rollback()  # Rollback on error
        finally:
            scoped_session_factory.remove()