import sys
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from agent.logger import agent_logger


IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import win32evtlog
else:
    win32evtlog = None


class EventLogMonitor:
    """
    Windows Event Log monitor.

    Collects selected Windows event IDs from several channels,
    parses Windows Event XML safely, maintains per-channel
    record-ID bookmarks, and generates security alerts.
    """

    EVENT_XML_NAMESPACE = (
        "http://schemas.microsoft.com/win/2004/08/events/event"
    )

    def __init__(self):
        # agent/bookmarks.json
        self.bookmarks_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "bookmarks.json",
        )

        self.bookmarks = {}
        self.load_bookmarks()

        # Event IDs we care about.
        self.monitored_event_ids = {
            # Security / authentication
            4624,
            4625,
            4688,
            4689,
            1102,
            4720,
            4726,

            # System / services
            7045,
            7036,

            # Sysmon
            1,
            3,
            7,
            10,
            11,
            13,
            22,
        }

        # Windows Event Log channels.
        self.channels = [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-Sysmon/Operational",
        ]

    # ------------------------------------------------------------------
    # BOOKMARKS
    # ------------------------------------------------------------------

    def load_bookmarks(self):
        """Load event-record bookmarks from disk."""
        try:
            if not os.path.exists(self.bookmarks_file):
                self.bookmarks = {}
                return

            with open(self.bookmarks_file, "r", encoding="utf-8") as file:
                data = json.load(file)

            if isinstance(data, dict):
                self.bookmarks = data
            else:
                self.bookmarks = {}

            agent_logger.info(
                f"Loaded event bookmarks: {self.bookmarks}"
            )

        except (json.JSONDecodeError, OSError) as exc:
            self.bookmarks = {}
            agent_logger.warning(
                f"Could not load event bookmarks: {exc}"
            )

        except Exception as exc:
            self.bookmarks = {}
            agent_logger.error(
                f"Unexpected error loading event bookmarks: {exc}"
            )

    def save_bookmarks(self):
        """Persist event-record bookmarks to disk."""
        try:
            os.makedirs(
                os.path.dirname(self.bookmarks_file),
                exist_ok=True,
            )

            temp_file = f"{self.bookmarks_file}.tmp"

            with open(temp_file, "w", encoding="utf-8") as file:
                json.dump(
                    self.bookmarks,
                    file,
                    indent=4,
                )

            os.replace(temp_file, self.bookmarks_file)

        except OSError as exc:
            agent_logger.error(
                f"Error saving event bookmarks: {exc}"
            )

        except Exception as exc:
            agent_logger.error(
                f"Unexpected error saving event bookmarks: {exc}"
            )

    # ------------------------------------------------------------------
    # XML HELPERS
    # ------------------------------------------------------------------

    @staticmethod
    def _local_name(tag):
        """
        Convert:
            {namespace}System
        into:
            System
        """
        if not tag:
            return ""

        return tag.rsplit("}", 1)[-1]

    @classmethod
    def _find_child(cls, parent, name):
        """
        Find a direct child regardless of XML namespace.
        """
        if parent is None:
            return None

        for child in list(parent):
            if cls._local_name(child.tag) == name:
                return child

        return None

    @classmethod
    def _find_children(cls, parent, name):
        """
        Find all direct children regardless of namespace.
        """
        if parent is None:
            return []

        return [
            child
            for child in list(parent)
            if cls._local_name(child.tag) == name
        ]

    @classmethod
    def _get_text(cls, parent, name, default=""):
        """Get text from a child node safely."""
        node = cls._find_child(parent, name)

        if node is None or node.text is None:
            return default

        return node.text.strip()

    # ------------------------------------------------------------------
    # EVENT XML PARSER
    # ------------------------------------------------------------------

    def parse_event_xml(self, xml_str):
        """
        Parse raw Windows Event XML.

        Windows Event XML normally contains a default namespace.
        This parser intentionally ignores namespaces so it works
        with Security, System, PowerShell, Defender and Sysmon events.
        """

        if not xml_str:
            return None

        try:
            # EvtRender normally returns a string.
            # Handle bytes too, just in case.
            if isinstance(xml_str, bytes):
                xml_str = xml_str.decode(
                    "utf-8",
                    errors="replace",
                )

            root = ET.fromstring(xml_str)

            # ----------------------------------------------------------
            # SYSTEM
            # ----------------------------------------------------------

            system = self._find_child(root, "System")

            if system is None:
                agent_logger.warning(
                    "Skipping Windows event: System node not found."
                )
                return None

            # Event ID
            event_id_text = self._get_text(
                system,
                "EventID",
                "0",
            )

            try:
                event_id = int(event_id_text)
            except (TypeError, ValueError):
                event_id = 0

            # Event Record ID
            event_record_id_text = self._get_text(
                system,
                "EventRecordID",
                "0",
            )

            try:
                event_record_id = int(event_record_id_text)
            except (TypeError, ValueError):
                event_record_id = 0

            # Provider
            provider_node = self._find_child(
                system,
                "Provider",
            )

            provider = ""

            if provider_node is not None:
                provider = provider_node.attrib.get(
                    "Name",
                    "",
                )

            # Channel
            channel = self._get_text(
                system,
                "Channel",
                "",
            )

            # Computer
            computer = self._get_text(
                system,
                "Computer",
                "",
            )

            # TimeCreated
            time_node = self._find_child(
                system,
                "TimeCreated",
            )

            timestamp = ""

            if time_node is not None:
                timestamp = time_node.attrib.get(
                    "SystemTime",
                    "",
                )

            # Level
            level = self._get_text(
                system,
                "Level",
                "",
            )

            # Task
            task = self._get_text(
                system,
                "Task",
                "",
            )

            # Opcode
            opcode = self._get_text(
                system,
                "Opcode",
                "",
            )

            # Keywords
            keywords = self._get_text(
                system,
                "Keywords",
                "",
            )

            # Security
            security_node = self._find_child(
                system,
                "Security",
            )

            user_id = ""

            if security_node is not None:
                user_id = security_node.attrib.get(
                    "UserID",
                    "",
                )

            # ----------------------------------------------------------
            # EVENT DATA
            # ----------------------------------------------------------

            event_data = {}

            data_container = self._find_child(
                root,
                "EventData",
            )

            if data_container is not None:
                for data_node in self._find_children(
                    data_container,
                    "Data",
                ):
                    name = data_node.attrib.get("Name")

                    if not name:
                        continue

                    event_data[name] = (
                        data_node.text or ""
                    ).strip()

            # ----------------------------------------------------------
            # USER DATA
            # ----------------------------------------------------------

            user_data = {}

            userdata_container = self._find_child(
                root,
                "UserData",
            )

            if userdata_container is not None:
                for child in list(userdata_container):
                    child_name = self._local_name(
                        child.tag
                    )

                    # Store direct text if available.
                    if child.text and child.text.strip():
                        user_data[child_name] = (
                            child.text.strip()
                        )

                    # Store nested fields.
                    for sub in list(child):
                        sub_name = self._local_name(
                            sub.tag
                        )

                        user_data[sub_name] = (
                            sub.text or ""
                        ).strip()

            # EventData has priority because it usually contains
            # the named Windows event fields we need.
            combined_details = {
                **user_data,
                **event_data,
            }

            return {
                "event_id": event_id,
                "event_record_id": event_record_id,
                "provider": provider,
                "channel": channel,
                "computer": computer,
                "timestamp": timestamp,
                "level": level,
                "task": task,
                "opcode": opcode,
                "keywords": keywords,
                "user_id": user_id,
                "details": combined_details,
            }

        except ET.ParseError as exc:
            agent_logger.warning(
                f"Invalid Windows Event XML: {exc}"
            )
            return None

        except Exception as exc:
            agent_logger.error(
                f"Error parsing event XML: {exc}"
            )
            return None

    # ------------------------------------------------------------------
    # CHANNEL QUERY
    # ------------------------------------------------------------------

    def query_channel(self, channel_name):
        """
        Query a Windows Event Log channel for new events.
        """

        events = []

        if not IS_WINDOWS or win32evtlog is None:
            return events

        # Build:
        # EventID=4624 or EventID=4625 or ...
        ids_query = " or ".join(
            f"EventID={event_id}"
            for event_id in sorted(
                self.monitored_event_ids
            )
        )

        last_record_id = self.bookmarks.get(
            channel_name
        )

        if last_record_id:
            try:
                last_record_id = int(last_record_id)
            except (TypeError, ValueError):
                last_record_id = 0

        # --------------------------------------------------------------
        # Build XPath
        # --------------------------------------------------------------

        if last_record_id:
            xpath_query = (
                "*[System["
                f"EventRecordID > {last_record_id}"
                f" and ({ids_query})"
                "]]"
            )
        else:
            # First run: only inspect the previous 60 minutes.
            utc_now = datetime.now(timezone.utc)

            start_time = (
                utc_now - timedelta(minutes=60)
            ).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )

            xpath_query = (
                "*[System["
                "TimeCreated["
                f"@SystemTime >= '{start_time}'"
                "]"
                f" and ({ids_query})"
                "]]"
            )

        query_handle = None

        try:
            query_handle = win32evtlog.EvtQuery(
                channel_name,
                win32evtlog.EvtQueryChannelPath,
                xpath_query,
            )

            highest_record_id = (
                int(last_record_id)
                if last_record_id
                else 0
            )

            while True:
                try:
                    event_handles = win32evtlog.EvtNext(
                        query_handle,
                        10,
                        2000,
                        0,
                    )
                except Exception as exc:
                    agent_logger.debug(
                        f"EvtNext failed for "
                        f"'{channel_name}': {exc}"
                    )
                    break

                if not event_handles:
                    break

                for event_handle in event_handles:
                    try:
                        xml_str = win32evtlog.EvtRender(
                            event_handle,
                            win32evtlog.EvtRenderEventXml,
                        )

                        parsed = self.parse_event_xml(
                            xml_str
                        )

                        if parsed is None:
                            continue

                        events.append(parsed)

                        record_id = parsed.get(
                            "event_record_id",
                            0,
                        )

                        try:
                            record_id = int(record_id)
                        except (TypeError, ValueError):
                            record_id = 0

                        if record_id > highest_record_id:
                            highest_record_id = record_id

                    except Exception as exc:
                        agent_logger.debug(
                            f"Event render error in "
                            f"'{channel_name}': {exc}"
                        )

                    finally:
                        try:
                            event_handle.Close()
                        except Exception:
                            pass

            # Update bookmark only after successful processing.
            if highest_record_id > 0:
                self.bookmarks[channel_name] = (
                    highest_record_id
                )

        except Exception as exc:
            # Missing channels are normal on systems where Sysmon
            # or certain Windows components are not installed.
            agent_logger.debug(
                f"Could not query channel "
                f"'{channel_name}': {exc}"
            )

        finally:
            if query_handle is not None:
                try:
                    query_handle.Close()
                except Exception:
                    pass

        return events

    # ------------------------------------------------------------------
    # MAIN CHECK
    # ------------------------------------------------------------------

    def check_events(self):
        """
        Poll all configured Windows Event Log channels.
        """

        if not IS_WINDOWS:
            return {
                "logs": [],
                "alerts": [],
            }

        collected_logs = []
        alerts = []

        for channel in self.channels:
            try:
                logs = self.query_channel(
                    channel
                )

                for log in logs:
                    collected_logs.append(log)

                    alert = (
                        self.evaluate_log_for_alerts(
                            log
                        )
                    )

                    if alert:
                        alerts.append(alert)

            except Exception as exc:
                # One broken channel must never stop
                # the entire EDR scheduler.
                agent_logger.error(
                    f"Event monitoring error for "
                    f"channel '{channel}': {exc}"
                )

        self.save_bookmarks()

        return {
            "logs": collected_logs,
            "alerts": alerts,
        }

    # ------------------------------------------------------------------
    # ALERT DETECTION
    # ------------------------------------------------------------------

    def evaluate_log_for_alerts(self, log):
        """
        Convert selected Windows Event IDs into EDR alerts.

        Severity values are intentionally lowercase because
        the Django backend stores:
            critical / high / medium / low / info
        """

        if not log:
            return None

        try:
            event_id = int(
                log.get("event_id", 0)
            )
        except (TypeError, ValueError):
            return None

        details = log.get(
            "details",
            {},
        )

        if not isinstance(details, dict):
            details = {}

        # --------------------------------------------------------------
        # 4625 - Failed Logon
        # --------------------------------------------------------------

        if event_id == 4625:
            username = details.get(
                "TargetUserName",
                "Unknown",
            )

            ip_address = details.get(
                "IpAddress",
                details.get(
                    "IpAddressV6",
                    "Unknown",
                ),
            )

            return {
                "type": "Failed Logon Attempt",
                "severity": "medium",
                "description": (
                    f"Failed logon attempt for user "
                    f"'{username}' from IP "
                    f"{ip_address}."
                ),
                "mitre_technique": "T1110",
                "recommendation": (
                    "Check whether the account is "
                    "authorized and monitor the source "
                    "IP for brute-force activity."
                ),
                "details": log,
            }

        # --------------------------------------------------------------
        # 4720 - User Account Created
        # --------------------------------------------------------------

        if event_id == 4720:
            username = details.get(
                "TargetUserName",
                "Unknown",
            )

            creator = details.get(
                "SubjectUserName",
                "Unknown",
            )

            return {
                "type": "New Local User Created",
                "severity": "high",
                "description": (
                    f"New local account "
                    f"'{username}' was created by "
                    f"'{creator}'."
                ),
                "mitre_technique": "T1136.001",
                "recommendation": (
                    "Verify whether this account "
                    "creation was authorized."
                ),
                "details": log,
            }

        # --------------------------------------------------------------
        # 7045 - New Windows Service
        # --------------------------------------------------------------

        if event_id == 7045:
            service_name = details.get(
                "ServiceName",
                "Unknown",
            )

            image_path = details.get(
                "ImagePath",
                "Unknown",
            )

            image_path_lower = str(
                image_path
            ).lower()

            suspicious = (
                "temp" in image_path_lower
                or "\\appdata\\" in image_path_lower
                or "/appdata/" in image_path_lower
            )

            severity = (
                "critical"
                if suspicious
                else "high"
            )

            return {
                "type": "New Service Created",
                "severity": severity,
                "description": (
                    f"A new service "
                    f"'{service_name}' was registered "
                    f"with image path: "
                    f"{image_path}"
                ),
                "mitre_technique": "T1543.003",
                "recommendation": (
                    "Verify whether the service is "
                    "authorized. Investigate the binary "
                    "and its execution path if unknown."
                ),
                "details": log,
            }

        return None