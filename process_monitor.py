import psutil
from datetime import datetime


def get_process_details():
    processes = []

    for process in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username", "status"]
    ):
        try:
            info = process.info

            processes.append(
                {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": info.get("name"),
                    "path": info.get("exe"),
                    "username": info.get("username"),
                    "status": info.get("status"),
                }
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return processes


def print_processes(processes):
    print("\n" + "=" * 100)
    print("WINDOWS PROCESS MONITOR")
    print("=" * 100)

    print(
        f"{'PID':<8}"
        f"{'PPID':<8}"
        f"{'PROCESS NAME':<30}"
        f"{'STATUS':<15}"
    )

    print("-" * 100)

    for process in processes:
        print(
            f"{str(process['pid']):<8}"
            f"{str(process['ppid']):<8}"
            f"{str(process['name'] or 'Unknown')[:28]:<30}"
            f"{str(process['status'] or 'Unknown'):<15}"
        )


if __name__ == "__main__":
    process_list = get_process_details()

    print_processes(process_list)

    print("\nTotal processes detected:", len(process_list))