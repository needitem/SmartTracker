import os
import sys
import tkinter as tk
from dump.logging_config import setup_logging
from dump.privilage import ensure_admin, is_admin
from gui.process_selector import ProcessSelector
import logging


def main():
    # Initialize logging
    logger = setup_logging()

    # Ensure the script is running with admin privileges
    ensure_admin()

    # Verify admin status
    if is_admin():
        logger.info("Administrator privileges confirmed.")
    else:
        logger.error("Failed to acquire administrator privileges.")
        sys.exit(1)

    # Check operating system
    if os.name != "nt":
        root = tk.Tk()
        root.withdraw()
        logger.error("Attempted to run on unsupported operating system.")
        tk.messagebox.showerror("Unsupported OS", "This script only supports Windows.")
        sys.exit(1)

    # Initialize GUI
    root = tk.Tk()
    root.title("Process Selector")
    root.geometry("800x600")
    logger.info("Starting GUI application.")

    app = ProcessSelector(parent=root)
    app.pack(fill=tk.BOTH, expand=True)

    root.mainloop()
    logger.info("GUI application terminated.")


if __name__ == "__main__":
    main()
