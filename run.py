# run.py

from app import create_app
from app.scheduler import start_scheduler
from threading import Thread
from app import website_update

def run_app():
    # Create Flask app instance
    app = create_app()

    # Start the APScheduler in a separate thread so it doesn't block the main app
    scheduler_thread = Thread(target=start_scheduler)
    scheduler_thread.daemon = True  # Ensure this thread exits when the app exits
    scheduler_thread.start()

    with app.app_context():
        app.run(debug=True, use_reloader=False)  # Don't use reloader to avoid starting multiple threads
        

if __name__ == "__main__":
    run_app()