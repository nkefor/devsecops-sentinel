"""Notification dispatcher that routes alerts based on severity."""
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field

from sentinel.notifications.slack import SlackNotifier
from sentinel.notifications.email_notifier import EmailNotifier


@dataclass
class NotificationConfig:
    """Configuration for notification routing."""
    slack_enabled: bool = True
    slack_severities: List[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    email_enabled: bool = False
    email_severities: List[str] = field(default_factory=lambda: ["CRITICAL"])


class NotificationDispatcher:
    """
    Routes notifications to appropriate channels based on severity.

    Supports multiple notification channels with severity-based routing.
    """

    def __init__(
        self,
        slack: Optional[SlackNotifier] = None,
        email: Optional[EmailNotifier] = None,
        config: Optional[NotificationConfig] = None
    ):
        """
        Initialize the notification dispatcher.

        Args:
            slack: Slack notifier instance
            email: Email notifier instance
            config: Notification routing configuration
        """
        self.slack = slack or SlackNotifier()
        self.email = email or EmailNotifier()
        self.config = config or NotificationConfig()

        # Track sent notifications to avoid duplicates
        self._sent: Dict[str, set] = {
            "slack": set(),
            "email": set()
        }

    def notify_vulnerability(
        self,
        vulnerability: Dict[str, Any],
        pr_url: Optional[str] = None,
        status: str = "detected"
    ) -> Dict[str, bool]:
        """
        Send vulnerability notification to appropriate channels.

        Args:
            vulnerability: Vulnerability data dictionary
            pr_url: URL of the created PR (if any)
            status: Status of the vulnerability

        Returns:
            Dictionary of channel -> success status
        """
        results = {}
        severity = vulnerability.get("severity", "MEDIUM")
        check_id = vulnerability.get("check_id", "unknown")

        # Avoid duplicate notifications
        notification_key = f"{check_id}:{status}"

        # Send to Slack if severity matches
        if (
            self.config.slack_enabled
            and severity in self.config.slack_severities
            and self.slack.is_available()
            and notification_key not in self._sent["slack"]
        ):
            results["slack"] = self.slack.send_vulnerability_alert(
                vulnerability, pr_url, status
            )
            if results["slack"]:
                self._sent["slack"].add(notification_key)

        # Send to Email if severity matches
        if (
            self.config.email_enabled
            and severity in self.config.email_severities
            and self.email.is_available()
            and notification_key not in self._sent["email"]
        ):
            results["email"] = self.email.send_vulnerability_alert(
                vulnerability, pr_url, status
            )
            if results["email"]:
                self._sent["email"].add(notification_key)

        return results

    def notify_summary(
        self,
        total_found: int,
        total_fixed: int,
        total_failed: int,
        critical_count: int = 0,
        high_count: int = 0,
        details: Optional[List[Dict]] = None
    ) -> Dict[str, bool]:
        """
        Send summary notification to all configured channels.

        Args:
            total_found: Total vulnerabilities found
            total_fixed: Successfully fixed count
            total_failed: Failed to fix count
            critical_count: Critical severity count
            high_count: High severity count
            details: Optional list of vulnerability details

        Returns:
            Dictionary of channel -> success status
        """
        results = {}

        # Always send summary if channel is available
        if self.config.slack_enabled and self.slack.is_available():
            results["slack"] = self.slack.send_summary(
                total_found, total_fixed, total_failed,
                critical_count, high_count
            )

        if self.config.email_enabled and self.email.is_available():
            results["email"] = self.email.send_summary(
                total_found, total_fixed, total_failed,
                critical_count, high_count, details
            )

        return results

    def notify_error(
        self,
        error_message: str,
        context: Optional[Dict] = None
    ) -> Dict[str, bool]:
        """
        Send error notification to all configured channels.

        Args:
            error_message: Error description
            context: Optional context information

        Returns:
            Dictionary of channel -> success status
        """
        results = {}

        error_vulnerability = {
            "check_id": "SENTINEL_ERROR",
            "check_name": error_message,
            "severity": "CRITICAL",
            "file_path": context.get("file", "N/A") if context else "N/A",
            "cis_benchmark": "N/A"
        }

        if self.slack.is_available():
            results["slack"] = self.slack.send_vulnerability_alert(
                error_vulnerability, status="error"
            )

        return results

    def reset_tracking(self):
        """Reset notification tracking (for testing)."""
        self._sent = {"slack": set(), "email": set()}

    @classmethod
    def from_config(cls, config_dict: Dict) -> 'NotificationDispatcher':
        """
        Create dispatcher from configuration dictionary.

        Args:
            config_dict: Configuration dictionary

        Returns:
            Configured NotificationDispatcher instance
        """
        notifications_config = config_dict.get("notifications", {})

        slack_config = notifications_config.get("slack", {})
        email_config = notifications_config.get("email", {})

        slack = SlackNotifier(
            webhook_url=slack_config.get("webhook_url"),
            channel=slack_config.get("channel"),
            enabled=slack_config.get("enabled", True)
        )

        email = EmailNotifier(
            recipients=email_config.get("recipients"),
            enabled=email_config.get("enabled", False)
        )

        config = NotificationConfig(
            slack_enabled=slack_config.get("enabled", True),
            slack_severities=slack_config.get("notify_on", ["CRITICAL", "HIGH"]),
            email_enabled=email_config.get("enabled", False),
            email_severities=email_config.get("notify_on", ["CRITICAL"])
        )

        return cls(slack=slack, email=email, config=config)
