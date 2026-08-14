"""HTTP client used by the Sentinel EDR Windows agent.

The client authenticates with the Django REST API using Simple JWT and ships
endpoint telemetry to the backend. Credentials can be supplied through
EDR_AGENT_USERNAME / EDR_AGENT_PASSWORD environment variables; config.json
is used as the local fallback for development.
"""

import os
import sys
import time
from typing import Any, Dict, Optional

import requests

from agent.logger import agent_logger
from agent.utils import (
    load_config,
    save_config,
    get_hostname,
    get_ip_address,
)


class APIClient:
    """Small, resilient REST client for the Sentinel EDR backend."""

    def __init__(self) -> None:
        self.config = load_config()

        # --------------------------------------------------------------
        # Backend URL
        # --------------------------------------------------------------
        raw_api_url = (
            os.environ.get("EDR_API_URL")
            or self.config.get("api_url")
            or "http://127.0.0.1:5000"
        )

        self.api_url = str(raw_api_url).strip().rstrip("/")

        # --------------------------------------------------------------
        # Agent identity
        # --------------------------------------------------------------
        self.agent_id = (
            os.environ.get("EDR_AGENT_ID")
            or self.config.get("agent_id")
            or "windows-endpoint-01"
        )

        # --------------------------------------------------------------
        # Authentication credentials
        # --------------------------------------------------------------
        self.username = (
            os.environ.get("EDR_AGENT_USERNAME")
            or self.config.get("username")
            or "agent_user"
        )

        self.password = (
            os.environ.get("EDR_AGENT_PASSWORD")
            or self.config.get("password")
            or ""
        )

        # --------------------------------------------------------------
        # JWT tokens
        # --------------------------------------------------------------
        self.token = self.config.get("auth_token") or ""

        self.refresh_token = (
            self.config.get("auth_refresh_token") or ""
        )

        self.headers: Dict[str, str] = {}

        # Persistent HTTP session
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
            }
        )

        # Prevent continuous authentication spam when credentials
        # are invalid.
        self._auth_retry_after = 0.0
        self._auth_failure_backoff = 10.0

        self._set_auth_header()

    # ==================================================================
    # AUTHENTICATION
    # ==================================================================

    def _set_auth_header(self) -> None:
        """Update Authorization header from current access token."""

        if self.token:
            self.headers = {
                "Authorization": f"Bearer {self.token}"
            }
        else:
            self.headers = {}

    def _save_auth_tokens(self) -> None:
        """Persist JWT tokens into local configuration."""

        self.config["auth_token"] = self.token
        self.config["auth_refresh_token"] = self.refresh_token

        save_config(self.config)

    def login(self, force: bool = False) -> bool:
        """
        Authenticate with Django Simple JWT.

        Returns:
            True  -> authentication successful
            False -> authentication failed
        """

        now = time.monotonic()

        # Avoid repeated login attempts every scheduler cycle.
        if not force and now < self._auth_retry_after:
            return False

        # Validate credentials before sending request.
        if not self.username or not self.password:
            agent_logger.error(
                "EDR authentication credentials are missing. "
                "Set EDR_AGENT_USERNAME/EDR_AGENT_PASSWORD or "
                "configure agent/config.json."
            )

            self._auth_retry_after = (
                now + self._auth_failure_backoff
            )

            return False

        url = f"{self.api_url}/api/token/"

        payload = {
            "username": self.username,
            "password": self.password,
        }

        try:
            agent_logger.info(
                "Authenticating EDR agent user '%s' against %s",
                self.username,
                url,
            )

            response = self.session.post(
                url,
                json=payload,
                timeout=10,
            )

            # ----------------------------------------------------------
            # SUCCESS
            # ----------------------------------------------------------
            if response.status_code == 200:
                data = response.json()

                access = data.get("access")
                refresh = data.get("refresh")

                if not access:
                    agent_logger.error(
                        "Authentication succeeded but no access token "
                        "was returned."
                    )

                    self._auth_retry_after = (
                        now + self._auth_failure_backoff
                    )

                    return False

                self.token = access
                self.refresh_token = refresh or ""

                self._set_auth_header()

                self._auth_retry_after = 0.0

                self._save_auth_tokens()

                agent_logger.info(
                    "Authentication successful. JWT acquired."
                )

                return True

            # ----------------------------------------------------------
            # INVALID USERNAME / PASSWORD
            # ----------------------------------------------------------
            if response.status_code == 401:
                agent_logger.error(
                    "Authentication failed (401). Backend rejected "
                    "username/password. For the bundled demo database "
                    "use agent_user / agent_password_123."
                )

            else:
                agent_logger.error(
                    "Authentication failed: %s - %s",
                    response.status_code,
                    response.text[:500],
                )

            self._auth_retry_after = (
                now + self._auth_failure_backoff
            )

            return False

        except requests.RequestException as exc:
            agent_logger.error(
                "Authentication error contacting backend: %s",
                exc,
            )

            self._auth_retry_after = (
                now + self._auth_failure_backoff
            )

            return False

        except ValueError as exc:
            agent_logger.error(
                "Backend returned invalid JSON during authentication: %s",
                exc,
            )

            self._auth_retry_after = (
                now + self._auth_failure_backoff
            )

            return False

    def refresh_access_token(self) -> bool:
        """
        Try to obtain a new access token using the refresh token.
        """

        if not self.refresh_token:
            return False

        url = f"{self.api_url}/api/token/refresh/"

        try:
            response = self.session.post(
                url,
                json={
                    "refresh": self.refresh_token
                },
                timeout=10,
            )

            if response.status_code != 200:
                return False

            data = response.json()

            access = data.get("access")

            if not access:
                return False

            self.token = access

            self._set_auth_header()

            self._save_auth_tokens()

            agent_logger.info(
                "JWT access token refreshed successfully."
            )

            return True

        except (requests.RequestException, ValueError) as exc:
            agent_logger.debug(
                "JWT refresh failed: %s",
                exc,
            )

            return False

    def check_token(self) -> bool:
        """Ensure the client has an access token."""

        if self.token:
            return True

        return self.login()

    # ==================================================================
    # HTTP HELPERS
    # ==================================================================

    @staticmethod
    def _json_or_empty(response: requests.Response) -> Any:
        """Safely parse JSON response."""

        if not response.content:
            return {}

        try:
            return response.json()
        except ValueError:
            return {}

    def _build_payload(
        self,
        payload: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Create a copy of payload and add endpoint identity.
        """

        data = dict(payload or {})

        data.setdefault(
            "hostname",
            get_hostname(),
        )

        data.setdefault(
            "ip_address",
            get_ip_address(),
        )

        data.setdefault(
            "agent_id",
            self.agent_id,
        )

        return data

    def _send_post(
        self,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
    ):
        """
        POST JSON data.

        On HTTP 401:
        1. Try refresh token.
        2. If refresh fails, perform fresh login.
        3. Retry once.
        """

        if not self.check_token():
            return None

        url = f"{self.api_url}/{path.lstrip('/')}"

        body = self._build_payload(payload)

        for attempt in range(2):

            try:
                response = self.session.post(
                    url,
                    json=body,
                    headers=self.headers,
                    timeout=15,
                )

                # ------------------------------------------------------
                # TOKEN EXPIRED / INVALID
                # ------------------------------------------------------
                if response.status_code == 401:

                    recovered = self.refresh_access_token()

                    if not recovered:
                        recovered = self.login(force=True)

                    if recovered and attempt == 0:
                        continue

                    agent_logger.error(
                        "Authentication rejected by %s.",
                        path,
                    )

                    return None

                # ------------------------------------------------------
                # SUCCESS
                # ------------------------------------------------------
                if response.status_code in (
                    200,
                    201,
                    202,
                    204,
                ):
                    return self._json_or_empty(response)

                # ------------------------------------------------------
                # OTHER HTTP ERROR
                # ------------------------------------------------------
                agent_logger.error(
                    "Failed to POST %s: %s - %s",
                    path,
                    response.status_code,
                    response.text[:500],
                )

                return None

            except requests.RequestException as exc:

                agent_logger.error(
                    "Error posting to %s: %s",
                    path,
                    exc,
                )

                if attempt == 0:
                    time.sleep(2)

        return None

    def _send_get(self, path: str):
        """
        GET JSON data.

        Automatically attempts token refresh/re-login on HTTP 401.
        """

        if not self.check_token():
            return None

        url = f"{self.api_url}/{path.lstrip('/')}"

        for attempt in range(2):

            try:
                response = self.session.get(
                    url,
                    headers=self.headers,
                    timeout=15,
                )

                if response.status_code == 401:

                    recovered = self.refresh_access_token()

                    if not recovered:
                        recovered = self.login(force=True)

                    if recovered and attempt == 0:
                        continue

                    agent_logger.error(
                        "Authentication rejected by %s.",
                        path,
                    )

                    return None

                if response.status_code == 200:
                    return self._json_or_empty(response)

                agent_logger.error(
                    "Failed to GET %s: %s - %s",
                    path,
                    response.status_code,
                    response.text[:500],
                )

                return None

            except requests.RequestException as exc:

                agent_logger.error(
                    "Error getting %s: %s",
                    path,
                    exc,
                )

                if attempt == 0:
                    time.sleep(2)

        return None

    # ==================================================================
    # TELEMETRY
    # ==================================================================

    def send_process_telemetry(self, processes):
        return self._send_post(
            "/api/telemetry/processes/",
            {
                "processes": processes
            },
        )

    def send_service_telemetry(self, services):
        return self._send_post(
            "/api/telemetry/services/",
            {
                "services": services
            },
        )

    def send_eventlog_telemetry(self, logs):
        return self._send_post(
            "/api/telemetry/logs/",
            {
                "logs": logs
            },
        )

    def send_system_health(self, health_data):
        return self._send_post(
            "/api/telemetry/health/",
            health_data,
        )

    def send_alert(self, alert_data):
        return self._send_post(
            "/api/alerts/create/",
            alert_data,
        )

    # ==================================================================
    # AGENT REGISTRATION
    # ==================================================================

    def register_agent(self):

        payload = {
            "os_info": (
                "Windows"
                if sys.platform == "win32"
                else "Linux/Mock"
            ),
            "agent_version": "1.0.0",
        }

        return self._send_post(
            "/api/agent/register/",
            payload,
        )

    def send_heartbeat(self):

        return self._send_post(
            "/api/agent/heartbeat/",
            {},
        )

    # ==================================================================
    # NETWORK
    # ==================================================================

    def send_network_telemetry(self, connections):

        return self._send_post(
            "/api/telemetry/network/",
            {
                "connections": connections
            },
        )

    # ==================================================================
    # IOC
    # ==================================================================

    def get_active_iocs(self):
        """Fetch active IOC rules from Django."""

        result = self._send_get(
            "/api/iocs/active/"
        )

        if isinstance(result, list):
            return result

        if isinstance(result, dict):

            rules = result.get("results")

            if isinstance(rules, list):
                return rules

        return []