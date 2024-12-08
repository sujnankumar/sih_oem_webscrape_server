# run.py

from app import create_app
from app.scheduler import start_scheduler
from threading import Thread

def run_app():
    # Create Flask app instance
    app = create_app()

    # Start the APScheduler in a separate thread so it doesn't block the main app
    scheduler_thread = Thread(target=start_scheduler)
    scheduler_thread.daemon = True  # Ensure this thread exits when the app exits
    scheduler_thread.start()

    # Run the Flask app
    app.run(debug=True, use_reloader=False)  # Don't use reloader to avoid starting multiple threads

if __name__ == "__main__":
    run_app()
