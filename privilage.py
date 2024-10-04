import ctypes
import sys
import os
from tkinter import messagebox


def is_admin():
    """
    Checks if the script is running with administrator privileges.

    Returns:
        bool: True if the script has admin rights, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    """
    Re-runs the current script with administrator privileges.

    This function triggers a UAC (User Account Control) prompt to request elevated permissions.
    If the user consents, the script restarts with admin rights. If not, it exits gracefully.
    """
    try:
        # Get the absolute path of the current script
        script = os.path.abspath(sys.argv[0])

        # Reconstruct the command-line arguments
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])

        # Execute the script with admin privileges
        ctypes.windll.shell32.ShellExecuteW(
            None,  # hwnd
            "runas",  # Operation to perform
            sys.executable,  # The executable (Python interpreter)
            f'"{script}" {params}',  # Parameters: script path and arguments
            None,  # Directory
            1,  # Show command (1 = SW_SHOWNORMAL)
        )
    except Exception as e:
        messagebox.showerror("Error", f"Failed to elevate privileges: {e}")
        sys.exit(1)


def ensure_admin():
    """
    Ensures that the script is running with administrator privileges.
    If not, it will attempt to relaunch the script with admin rights.
    """
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False

    if not is_admin:
        # Relaunch the script with admin rights
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                " ".join([f'"{arg}"' for arg in sys.argv]),
                None,
                1,
            )
            sys.exit(0)
        except Exception as e:
            logging.error(f"Failed to acquire administrator privileges: {e}")
            print(f"Error: Failed to acquire administrator privileges:\n{e}")
            sys.exit(1)
