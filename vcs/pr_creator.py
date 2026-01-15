"""GitHub Pull Request creator for security fixes."""
import os
from typing import Optional
from github import Github, GithubException
from models.vulnerability import Vulnerability


class PRCreator:
    """
    Creates GitHub Pull Requests for security vulnerability fixes.

    Handles branch creation, file updates, and PR creation with
    enhanced descriptions including compliance information.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        repo_name: Optional[str] = None,
        base_branch: str = "main"
    ):
        """
        Initialize the PR creator.

        Args:
            token: GitHub personal access token (defaults to GITHUB_TOKEN env var)
            repo_name: Repository in format "owner/repo" (defaults to GITHUB_REPOSITORY env var)
            base_branch: Base branch for PRs (default: main)
        """
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.repo_name = repo_name or os.getenv("GITHUB_REPOSITORY")
        self.base_branch = base_branch
        self.github = None
        self.repo = None
        self.dry_run = False

        if self.token and self.repo_name:
            try:
                self.github = Github(self.token)
                self.repo = self.github.get_repo(self.repo_name)
            except GithubException as e:
                print(f"[PRCreator] Warning: Could not connect to GitHub: {e}")
                self.dry_run = True
        else:
            self.dry_run = True
            if not self.token:
                print("[PRCreator] No GitHub token provided - running in dry-run mode")
            if not self.repo_name:
                print("[PRCreator] No repository specified - running in dry-run mode")

    def is_available(self) -> bool:
        """Check if GitHub integration is available."""
        return self.github is not None and self.repo is not None

    def create_fix_pr(
        self,
        vulnerability: Vulnerability,
        fixed_content: str,
        pr_body: str
    ) -> Optional[str]:
        """
        Create a Pull Request with the security fix.

        Args:
            vulnerability: The vulnerability being fixed
            fixed_content: The fixed file content
            pr_body: The PR description body

        Returns:
            PR URL if successful, None otherwise
        """
        if self.dry_run:
            return self._dry_run_output(vulnerability, fixed_content, pr_body)

        branch_name = self._generate_branch_name(vulnerability)

        try:
            # Step 1: Create the branch
            if not self._create_branch(branch_name):
                return None

            # Step 2: Update the file
            if not self._update_file(vulnerability.file_path, fixed_content, branch_name, vulnerability):
                return None

            # Step 3: Create the PR
            pr_url = self._create_pull_request(vulnerability, branch_name, pr_body)
            return pr_url

        except GithubException as e:
            print(f"[PRCreator] GitHub API error: {e}")
            return None
        except Exception as e:
            print(f"[PRCreator] Unexpected error: {e}")
            return None

    def _generate_branch_name(self, vulnerability: Vulnerability) -> str:
        """Generate a unique branch name for the fix."""
        # Sanitize check_id for use in branch name
        safe_id = vulnerability.check_id.lower().replace("_", "-").replace(".", "-")
        return f"security/fix-{safe_id}"

    def _create_branch(self, branch_name: str) -> bool:
        """
        Create a new branch from the base branch.

        Args:
            branch_name: Name for the new branch

        Returns:
            True if successful (or branch exists), False otherwise
        """
        try:
            # Get the base branch SHA
            base = self.repo.get_branch(self.base_branch)

            # Try to create the branch
            try:
                self.repo.create_git_ref(
                    ref=f"refs/heads/{branch_name}",
                    sha=base.commit.sha
                )
                print(f"[PRCreator] Created branch: {branch_name}")
            except GithubException as e:
                if e.status == 422:  # Branch already exists
                    print(f"[PRCreator] Branch {branch_name} already exists, reusing")
                else:
                    raise

            return True

        except GithubException as e:
            print(f"[PRCreator] Error creating branch: {e}")
            return False

    def _update_file(
        self,
        file_path: str,
        new_content: str,
        branch_name: str,
        vulnerability: Vulnerability
    ) -> bool:
        """
        Update the file with the fixed content.

        Args:
            file_path: Path to the file to update
            new_content: The new file content
            branch_name: Branch to commit to
            vulnerability: Vulnerability details for commit message

        Returns:
            True if successful, False otherwise
        """
        try:
            # Get current file contents
            contents = self.repo.get_contents(file_path, ref=branch_name)

            # Commit message
            commit_msg = f"security: fix {vulnerability.check_id}\n\n{vulnerability.check_name}"

            # Update the file
            self.repo.update_file(
                path=contents.path,
                message=commit_msg,
                content=new_content,
                sha=contents.sha,
                branch=branch_name
            )
            print(f"[PRCreator] Updated file: {file_path}")
            return True

        except GithubException as e:
            print(f"[PRCreator] Error updating file: {e}")
            return False

    def _create_pull_request(
        self,
        vulnerability: Vulnerability,
        branch_name: str,
        pr_body: str
    ) -> Optional[str]:
        """
        Create the Pull Request.

        Args:
            vulnerability: Vulnerability being fixed
            branch_name: Source branch with the fix
            pr_body: PR description body

        Returns:
            PR URL if successful, None otherwise
        """
        try:
            # Check if PR already exists
            existing_prs = self.repo.get_pulls(
                state='open',
                head=f"{self.repo.owner.login}:{branch_name}"
            )

            for pr in existing_prs:
                print(f"[PRCreator] PR already exists: {pr.html_url}")
                return pr.html_url

            # Create new PR
            severity_emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
            }.get(vulnerability.severity.value, "⚪")

            pr_title = f"{severity_emoji} Fix: {vulnerability.check_id} - {vulnerability.check_name[:50]}"

            pr = self.repo.create_pull(
                title=pr_title,
                body=pr_body,
                head=branch_name,
                base=self.base_branch
            )

            # Add labels
            try:
                pr.add_to_labels("security", "automated")
                if vulnerability.severity.value in ["CRITICAL", "HIGH"]:
                    pr.add_to_labels("priority-high")
            except GithubException:
                pass  # Labels might not exist

            print(f"[PRCreator] Created PR: {pr.html_url}")
            return pr.html_url

        except GithubException as e:
            print(f"[PRCreator] Error creating PR: {e}")
            return None

    def _dry_run_output(
        self,
        vulnerability: Vulnerability,
        fixed_content: str,
        pr_body: str
    ) -> Optional[str]:
        """
        Output what would happen in dry-run mode.

        Args:
            vulnerability: The vulnerability being fixed
            fixed_content: The fixed file content
            pr_body: The PR description body

        Returns:
            "DRY_RUN" to indicate dry-run mode
        """
        print("\n" + "=" * 60)
        print("DRY RUN MODE - No GitHub operations performed")
        print("=" * 60)
        print(f"\nWould create PR for: {vulnerability.check_id}")
        print(f"File: {vulnerability.file_path}")
        print(f"Severity: {vulnerability.severity.value}")
        print(f"Branch: security/fix-{vulnerability.check_id.lower().replace('_', '-')}")
        print("\n--- PR BODY ---")
        print(pr_body[:500] + "..." if len(pr_body) > 500 else pr_body)
        print("\n--- FIXED CODE (first 50 lines) ---")
        fixed_lines = fixed_content.split('\n')[:50]
        print('\n'.join(fixed_lines))
        if len(fixed_content.split('\n')) > 50:
            print("... (truncated)")
        print("=" * 60 + "\n")

        return "DRY_RUN"
