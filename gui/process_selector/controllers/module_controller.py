import logging

logger = logging.getLogger(__name__)


class ModuleController:
    def __init__(self):
        pass

    def fetch_modules_by_pid(self, pid: int):
        """Fetch modules associated with the given PID."""
        try:
            modules = self.database.fetch_selected_modules_by_pids([pid])
            logger.info(f"Fetched {len(modules)} modules for PID={pid}")
            return modules
        except Exception as e:
            logger.error(f"Error fetching modules for PID={pid}: {e}")
            return []
