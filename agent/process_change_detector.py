from datetime import datetime


class ProcessChangeDetector:
    def __init__(self):
        self.previous_processes = {}

    def compare(self, current_processes):
        current_processes_map = {}

        for process in current_processes:
            pid = process.get("pid")

            if pid is None:
                continue

            current_processes_map[pid] = process

        new_processes = []

        for pid, process in current_processes_map.items():

            if pid not in self.previous_processes:
                new_processes.append(
                    {
                        "timestamp": datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        "event": "NEW_PROCESS",
                        "pid": process.get("pid"),
                        "ppid": process.get("ppid"),
                        "name": process.get("name"),
                        "path": process.get("path"),
                        "username": process.get("username"),
                    }
                )

        self.previous_processes = current_processes_map

        return new_processes