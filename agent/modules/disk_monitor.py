import psutil

from agent.logger import agent_logger


class DiskMonitor:
    """
    Collects filesystem capacity and disk I/O telemetry.
    """

    def get_metrics(self):
        partitions = []

        try:
            raw_partitions = psutil.disk_partitions(
                all=False
            )
        except Exception as exc:
            agent_logger.error(
                f"Unable to enumerate disk partitions: "
                f"{exc}"
            )

            raw_partitions = []

        for part in raw_partitions:

            try:
                mountpoint = (
                    getattr(
                        part,
                        "mountpoint",
                        "",
                    )
                    or ""
                )

                if not mountpoint:
                    continue

                usage = psutil.disk_usage(
                    mountpoint
                )

                partitions.append(
                    {
                        "device": getattr(
                            part,
                            "device",
                            "",
                        )
                        or "",
                        "mountpoint": mountpoint,
                        "fstype": getattr(
                            part,
                            "fstype",
                            "",
                        )
                        or "",
                        "total_bytes": int(
                            usage.total
                        ),
                        "used_bytes": int(
                            usage.used
                        ),
                        "free_bytes": int(
                            usage.free
                        ),
                        "disk_percent": float(
                            usage.percent
                        ),
                    }
                )

            except (
                PermissionError,
                FileNotFoundError,
                OSError,
            ):
                # Some Windows drives can disappear or become
                # inaccessible during enumeration.
                continue

            except Exception as exc:
                agent_logger.debug(
                    "Disk partition telemetry failed "
                    f"for '{getattr(part, 'mountpoint', '')}': "
                    f"{exc}"
                )

        # --------------------------------------------------------------
        # DISK I/O
        # --------------------------------------------------------------

        read_bytes = 0
        write_bytes = 0
        read_count = 0
        write_count = 0

        try:
            io = psutil.disk_io_counters()

            if io is not None:
                read_bytes = int(
                    getattr(
                        io,
                        "read_bytes",
                        0,
                    )
                    or 0
                )

                write_bytes = int(
                    getattr(
                        io,
                        "write_bytes",
                        0,
                    )
                    or 0
                )

                read_count = int(
                    getattr(
                        io,
                        "read_count",
                        0,
                    )
                    or 0
                )

                write_count = int(
                    getattr(
                        io,
                        "write_count",
                        0,
                    )
                    or 0
                )

        except Exception as exc:
            agent_logger.debug(
                f"Disk I/O counters unavailable: {exc}"
            )

        return {
            "partitions": partitions,
            "read_bytes": read_bytes,
            "write_bytes": write_bytes,
            "read_count": read_count,
            "write_count": write_count,
        }