"""Slack notification integration for DevSecOps Sentinel."""
import os
import json
from typing import Optional, List, Dict
from dataclasses import dataclass


@dataclass
class SlackMessage:
    """Represents a Slack message."""
    channel: str
    text: str
    blocks: Optional[List[Dict]] = None
    attachments: Optional[List[Dict]] = None


class SlackNotifier:
    """
    Slack notification sender for security alerts.

    Supports rich message formatting with severity-based colors.
    """

    SEVERITY_COLORS = {
        "CRITICAL": "#FF0000",  # Red
        "HIGH": "#FF8C00",      # Dark Orange
        "MEDIUM": "#FFD700",    # Gold
        "LOW": "#32CD32",       # Lime Green
        "INFO": "#1E90FF",      # Dodger Blue
    }

    SEVERITY_EMOJI = {
        "CRITICAL": ":rotating_light:",
        "HIGH": ":warning:",
        "MEDIUM": ":large_yellow_circle:",
        "LOW": ":large_green_circle:",
        "INFO": ":information_source:",
    }

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        channel: Optional[str] = None,
        enabled: bool = True
    ):
        """
        Initialize the Slack notifier.

        Args:
            webhook_url: Slack webhook URL (defaults to SLACK_WEBHOOK_URL env var)
            channel: Default channel to post to
            enabled: Whether notifications are enabled
        """
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        self.channel = channel or os.getenv("SLACK_CHANNEL", "#security-alerts")
        self.enabled = enabled and self.webhook_url is not None

        if not self.webhook_url and enabled:
            print("[Slack] Warning: No webhook URL provided. Notifications disabled.")

    def is_available(self) -> bool:
        """Check if Slack notifications are available."""
        return self.enabled and self.webhook_url is not None

    def send_vulnerability_alert(
        self,
        vulnerability: dict,
        pr_url: Optional[str] = None,
        status: str = "detected"
    ) -> bool:
        """
        Send a vulnerability alert to Slack.

        Args:
            vulnerability: Vulnerability data dictionary
            pr_url: URL of the created PR (if any)
            status: Status of the vulnerability (detected, fixed, failed)

        Returns:
            True if message sent successfully
        """
        if not self.is_available():
            return False

        severity = vulnerability.get("severity", "MEDIUM")
        check_id = vulnerability.get("check_id", "Unknown")
        check_name = vulnerability.get("check_name", "Security vulnerability detected")
        file_path = vulnerability.get("file_path", "Unknown file")
        cis_benchmark = vulnerability.get("cis_benchmark", "N/A")

        emoji = self.SEVERITY_EMOJI.get(severity, ":warning:")
        color = self.SEVERITY_COLORS.get(severity, "#808080")

        # Build message blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Security Alert: {check_id}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{severity}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:*\n{status.upper()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*File:*\n`{file_path}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*CIS Benchmark:*\n{cis_benchmark}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{check_name}"
                }
            }
        ]

        # Add PR link if available
        if pr_url and pr_url != "DRY_RUN":
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":pull_request: *Pull Request:* <{pr_url}|View PR>"
                }
            })

        # Add divider
        blocks.append({"type": "divider"})

        return self._send_message(blocks=blocks, color=color)

    def send_summary(
        self,
        total_found: int,
        total_fixed: int,
        total_failed: int,
        critical_count: int = 0,
        high_count: int = 0
    ) -> bool:
        """
        Send a summary notification.

        Args:
            total_found: Total vulnerabilities found
            total_fixed: Successfully fixed count
            total_failed: Failed to fix count
            critical_count: Critical severity count
            high_count: High severity count

        Returns:
            True if message sent successfully
        """
        if not self.is_available():
            return False

        # Determine overall status emoji
        if total_failed > 0 or critical_count > 0:
            status_emoji = ":x:"
            status_text = "Attention Required"
        elif total_fixed == total_found:
            status_emoji = ":white_check_mark:"
            status_text = "All Clear"
        else:
            status_emoji = ":warning:"
            status_text = "Partial Success"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Security Scan Summary",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Found:*\n{total_found}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Fixed:*\n{total_fixed}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Failed:*\n{total_failed}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:*\n{status_text}"
                    }
                ]
            }
        ]

        if critical_count > 0 or high_count > 0:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":rotating_light: *Critical:* {critical_count} | :warning: *High:* {high_count}"
                }
            })

        blocks.append({"type": "divider"})

        return self._send_message(blocks=blocks)

    def _send_message(
        self,
        text: str = "",
        blocks: Optional[List[Dict]] = None,
        color: str = "#808080"
    ) -> bool:
        """
        Send a message to Slack via webhook.

        Args:
            text: Fallback text
            blocks: Block kit blocks
            color: Attachment color

        Returns:
            True if sent successfully
        """
        try:
            import urllib.request

            payload = {
                "channel": self.channel,
                "text": text or "Security Sentinel Alert",
                "attachments": [{
                    "color": color,
                    "blocks": blocks or []
                }]
            }

            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={'Content-Type': 'application/json'}
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status == 200

        except Exception as e:
            print(f"[Slack] Error sending message: {e}")
            return False
