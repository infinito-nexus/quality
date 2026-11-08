import json
import os
import secrets

import launcher

TIER_DIGITS = "012"


class SpoolFull(Exception):
    pass


class Spool:
    def __init__(self, settings):
        self.spool = os.path.join(settings["state_dir"], "spool")
        self.reports = os.path.join(settings["state_dir"], "reports")

    def anonymous_queued(self):
        prefix = f"{launcher.TIERS.index('anonymous')}-"
        return sum(1 for name in os.listdir(self.spool) if name.startswith(prefix))

    def submit(self, tier, job):
        """
        Args:
            tier: member, registered or anonymous.
            job: The job as parse_job of the launcher reads it.

        Returns:
            The new job id, which is also the report link.
        """
        job_id = secrets.token_hex(16)
        temporary = os.path.join(self.spool, f".{job_id}.tmp")
        try:
            handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(job, stream)
            os.rename(temporary, os.path.join(self.spool, launcher.job_file_name(tier, job_id)))
        except OSError as error:
            if os.path.lexists(temporary):
                os.unlink(temporary)
            raise SpoolFull from error
        return job_id

    def status(self, job_id):
        """
        Args:
            job_id: Id from the report link.

        Returns:
            ("report", document), ("queued", None) while the job waits in the spool,
            ("running", None) once the launcher holds it, or (None, None) for an unknown id.
        """
        if not launcher.JOB_ID.match(job_id):
            return None, None
        try:
            with open(os.path.join(self.reports, f"{job_id}.json"), encoding="utf-8") as handle:
                return "report", json.load(handle)
        except FileNotFoundError:
            pass
        if any(os.path.exists(os.path.join(self.spool, f"{digit}-{job_id}.json")) for digit in TIER_DIGITS):
            return "queued", None
        if os.path.exists(os.path.join(self.reports, f"{job_id}.running")):
            return "running", None
        return None, None
