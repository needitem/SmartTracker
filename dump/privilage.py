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
    if not is_admin():
        logger.info("Administrator privileges not detected. Attempting to elevate.")
        try:
            run_as_admin()
            sys.exit(0)
        except Exception as e:
            logger.error(f"Failed to acquire administrator privileges: {e}")
            print(f"Error: Failed to acquire administrator privileges:\n{e}")
            sys.exit(1)
    else:
        logger.debug("Administrator privileges confirmed.")
