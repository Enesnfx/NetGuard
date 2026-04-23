import logging
from typing import Callable, Optional

logging.getLogger("apscheduler").setLevel(logging.WARNING)


class ScanScheduler:
    def __init__(self, scan_fn: Callable):
        from apscheduler.schedulers.background import BackgroundScheduler
        self._fn = scan_fn
        self._sched = BackgroundScheduler()
        self._job = None
        self._sched.start()

    def start(self, interval_minutes: int = 30):
        self.stop()
        from apscheduler.triggers.interval import IntervalTrigger
        self._job = self._sched.add_job(
            self._fn,
            trigger=IntervalTrigger(minutes=interval_minutes),
            id="netguard_scan",
            replace_existing=True,
        )

    def stop(self):
        if self._job:
            try:
                self._job.remove()
            except Exception:
                pass
            self._job = None

    def is_running(self) -> bool:
        return self._job is not None

    def shutdown(self):
        self._sched.shutdown(wait=False)
