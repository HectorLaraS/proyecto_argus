import os
import time
import subprocess

import win32event
import win32service
import win32serviceutil
import servicemanager

import win32job
import win32api
import win32con

PROJECT_ROOT = r"E:\cpkc_tac_python\argus"
PYTHON_EXE = os.path.join(PROJECT_ROOT, ".venv", "Scripts", "python.exe")

LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
STDOUT_LOG = os.path.join(LOG_DIR, "service_stdout.log")
STDERR_LOG = os.path.join(LOG_DIR, "service_stderr.log")

APP_ARGS = [PYTHON_EXE, "-m", "main_windows_argus"]


class WatchtowerService(win32serviceutil.ServiceFramework):
    _svc_name_ = "Argus"
    _svc_display_name_ = "Argus Service"
    _svc_description_ = "Argus 24/7 runner (pywin32)"

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.proc = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)

        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                for _ in range(20):
                    if self.proc.poll() is not None:
                        break
                    time.sleep(0.25)
                if self.proc.poll() is None:
                    self.proc.kill()
            except Exception:
                pass

    def SvcDoRun(self):
        os.chdir(PROJECT_ROOT)
        servicemanager.LogInfoMsg("Argus service starting...")

        # Crear un Job object para luego cerrar todos los hijos al terminar el padre
        hJob = win32job.CreateJobObject(None, "")
        extended_info = win32job.QueryInformationJobObject(hJob, win32job.JobObjectExtendedLimitInformation)
        extended_info['BasicLimitInformation']['LimitFlags'] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(hJob, win32job.JobObjectExtendedLimitInformation, extended_info)

        with open(STDOUT_LOG, "a", encoding="utf-8") as out, open(STDERR_LOG, "a", encoding="utf-8") as err:
            self.proc = subprocess.Popen(
                APP_ARGS,
                cwd=PROJECT_ROOT,
                stdout=out,
                stderr=err,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # ASIGNAMOS el proceso al Job Object
            win32job.AssignProcessToJobObject(hJob, win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, self.proc.pid))

            while True:
                rc = win32event.WaitForSingleObject(self.stop_event, 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    break

                if self.proc.poll() is not None:
                    servicemanager.LogErrorMsg(
                        f"Argus child exited with code {self.proc.returncode}. Restarting..."
                    )
                    time.sleep(3)
                    self.proc = subprocess.Popen(
                        APP_ARGS,
                        cwd=PROJECT_ROOT,
                        stdout=out,
                        stderr=err,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    win32job.AssignProcessToJobObject(hJob, win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, self.proc.pid))

        servicemanager.LogInfoMsg("Argus service stopped.")
        # Cuando sales del with / función, el "JobObject" se destruye y todos los hijos mueren


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(WatchtowerService)
