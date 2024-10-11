import ctypes
import sys
import os
import logging
from tkinter import messagebox

logger = logging.getLogger(__name__)


def is_admin() -> bool:
    """
    Check if the script is running with administrator privileges.

    Returns:
        bool: True if admin rights are present, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    """
    Relaunch the current script with administrator privileges.
    """
    try:
        script = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            f'"{script}" {params}',
            None,
            1,
        )
    except Exception as e:
        messagebox.showerror("Error", f"Failed to elevate privileges: {e}")
        logger.error(f"Failed to elevate privileges: {e}")
        sys.exit(1)


def ensure_admin():
    """
    Ensure the script is running with administrator privileges.
    If not, attempt to relaunch with elevated rights.
    """
    try:
        if not is_admin():
            logger.debug("Administrator privileges not detected. Attempting to relaunch as admin.")
            script = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            result = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                f'"{script}" {params}',
                None,
                1,
            )
            if result <= 32:
                logger.error(f"Failed to relaunch with admin privileges. ShellExecuteW returned: {result}")
                messagebox.showerror("Error", "Failed to acquire administrator privileges.")
            else:
                logger.info("Relaunched script with administrator privileges.")
            sys.exit(0)  # Exit the original process after relaunching
        else:
            logger.debug("Running with administrator privileges.")
    except Exception as e:
        logger.error(f"Exception occurred in ensure_admin: {e}")
        messagebox.showerror("Error", f"An error occurred while trying to acquire administrator privileges:\n{e}")
        sys.exit(1)