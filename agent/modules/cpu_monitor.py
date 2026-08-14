import psutil

from agent.logger import agent_logger


class CPUMonitor:
    """
    Collects CPU utilization and top CPU-consuming processes.
    """

    def get_metrics(self):
        try:
            # ----------------------------------------------------------
            # SYSTEM CPU
            # ----------------------------------------------------------

            cpu_percent = float(
                psutil.cpu_percent(
                    interval=0.2
                )
            )

            logical_cores = (
                psutil.cpu_count(
                    logical=True
                )
                or 0
            )

            physical_cores = (
                psutil.cpu_count(
                    logical=False
                )
                or 0
            )

            # ----------------------------------------------------------
            # PROCESS CPU SAMPLING
            # ----------------------------------------------------------

            processes = []

            try:
                process_list = list(
                    psutil.process_iter(
                        [
                            "pid",
                            "name",
                        ]
                    )
                )
            except Exception as exc:
                agent_logger.debug(
                    f"Could not enumerate processes "
                    f"for CPU monitoring: {exc}"
                )
                process_list = []

            # First sample.
            for proc in process_list:
                try:
                    proc.cpu_percent(
                        interval=None
                    )
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    continue
                except Exception:
                    continue

            # Short sampling window.
            if process_list:
                try:
                    psutil.cpu_percent(
                        interval=0.2
                    )
                except Exception:
                    pass

            # Second sample.
            for proc in process_list:

                try:
                    info = proc.info

                    pid = info.get(
                        "pid"
                    )

                    name = (
                        info.get(
                            "name"
                        )
                        or "Unknown"
                    )

                    cpu = float(
                        proc.cpu_percent(
                            interval=None
                        )
                        or 0.0
                    )

                    if cpu <= 0.5:
                        continue

                    processes.append(
                        {
                            "pid": int(
                                pid
                            ),
                            "name": str(
                                name
                            ),
                            "cpu_percent": round(
                                cpu,
                                2,
                            ),
                        }
                    )

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    continue

                except (
                    TypeError,
                    ValueError,
                ):
                    continue

                except Exception as exc:
                    agent_logger.debug(
                        f"CPU process sample failed: "
                        f"{exc}"
                    )

            # ----------------------------------------------------------
            # TOP PROCESSES
            # ----------------------------------------------------------

            processes.sort(
                key=lambda item: item[
                    "cpu_percent"
                ],
                reverse=True,
            )

            top_processes = processes[
                :5
            ]

            return {
                "cpu_percent": round(
                    cpu_percent,
                    2,
                ),
                "cores_logical": int(
                    logical_cores
                ),
                "cores_physical": int(
                    physical_cores
                ),
                "top_cpu_processes": (
                    top_processes
                ),
            }

        except Exception as exc:
            agent_logger.error(
                f"Error in CPUMonitor: {exc}",
                exc_info=True,
            )

            return {
                "cpu_percent": 0.0,
                "cores_logical": 0,
                "cores_physical": 0,
                "top_cpu_processes": [],
            }