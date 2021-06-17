# Copyright (c) 2020 ARM Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Simplified new issue handling script for use with GitHub actions
#
"""Weekly reporting and tidying of mbed projects."""

import os
import logging
import traceback
import argparse
from github import Github, GithubException
from os.path import join
from contextlib import contextmanager
from mailer import Mailer
from mailer import Message

userlog = logging.getLogger("Weekly")

# Set logging level
userlog.setLevel(logging.DEBUG)

# Everything is output to the log file
logfile = os.path.join(os.getcwd(), 'weekly.log')
fh = logging.FileHandler(logfile)
fh.setLevel(logging.DEBUG)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

formatter = logging.Formatter('%(name)s: %(levelname)s - %(message)s')
ch.setFormatter(formatter)
fh.setFormatter(formatter)    

# add the handlers to the logger
userlog.addHandler(fh)
userlog.addHandler(ch)

GIT_ACCOUNT = "ARMmbed"
LOGIN = "mbedmain"
REPO_NAME = "mbed-os"
REPORT_RECIPIENTS = "iot-os-m-core@arm.com"
PROJECTS_TO_TIDY = ["Mbed Core", "Issue Severity", "Issue Workflow"]
REPORT_REPO = "Mbed Core"

@contextmanager
def exit_on_exception(text):
    try:
        yield
    except Exception as exc:
        userlog.error(text)
        userlog.exception(exc)
        os._exit(1)

def get_repo_and_org(github_class, git_account, repo_name):
    """Get the repo and user objects for the specified account and repo name.

    Args:
    github_class - GitHub object
    git_account - GitHub account
    repo_name - Repository to get the object for

    Returns:
    repo - Repository object for the specified repository name
    org - GitHub organization
    """
    repo_path = git_account + "/" + repo_name

    with exit_on_exception("Cannot access: " + str(repo_path)):
        repo = github_class.get_repo(repo_path, False)

    with exit_on_exception("Cannot get organization for: ARMmbed"):
        org = github_class.get_organization("ARMmbed")

    return repo, org

def get_project_obj(project_name, project_objs):
    """Return the project object matching the name, from the supplied list

    Args:
    project_name - GitHub project name
    project_objs - List of all project objects in the organisation
 
    Returns:
    The project object if found else None
    """

    for obj in project_objs:
        if project_name in obj.name:
            return obj

    return None

def produce_weekly_report(project_name, email_addr, project_objs):
    """Produce a weekly report using issues in the specified project.

    Report is emailed to the specified email_addr

    Args:
    project_name - GitHub project name
    email_addr - valid email address
    project_objs - list of GitHub project objects

    """

    proj_obj = get_project_obj(project_name, project_objs)
    if proj_obj is None:
        userlog.error("Cannot get project object for %s", proj_name)
        return

    column_objs = proj_obj.get_columns()

    email_body = (
        """<p>This ia an automated email for the Core OS weekly report</p> """
    )

    issues = []

    # Process project columns
    for column in column_objs:

        # Only interested in the Done and In progress columns
        if "Done" in column.name:
            userlog.info("Column '%s' found", column.name)
            card_status = "(Completed) "
        elif "In progress" in column.name:
            userlog.info("Column '%s' found", column.name)
            card_status = "(In-progress) "
        else:
            userlog.info("Column '%s' ignored", column.name)
            continue

        # Process card contents for the current column
        proj_cards = column.get_cards()
        for card in proj_cards:
            card_content = card.get_content()

            # Content can return an issue or PR, we only want issues
            if card_content.pull_request is not None:
                userlog.info("Ignoring Pull Request card type")
                continue

            if "mbed-os" in card_content.repository.name:
                card_repo = "Mbed OS: "
            elif "mbed-os-tools" in card_content.repository.name:
                card_repo = "Mbed CLI 1: "
            elif "mbed-tools" in card_content.repository.name:
                card_repo = "Mbed CLI 2: "
            else:
                continue

            labels = card_content.labels
            for label in labels:
                if "Bug" in label.name:
                    card_type = "Bugfix: "
                elif "Maintenance" in label.name:
                    card_type = "Maintenance: "
                else:
                    card_type = ""

            # Collate data into the correct category
            entry = dict(
                status = card_status,
                repo = card_repo,
                type = card_type,
                num = "#" + str(card_content.number) + " ",
                title = card_content.title
            )
            issues.append(entry)

    # Compose email contents
    for issue in issues:
        line = issue["status"] + issue["repo"] + issue["type"] + issue["num"] + issue["title"]
        email_body += """<p>%s</p>""" % line

    email_user(
        email_addr,
        "Weekly report data",
        email_body,
        "ciarmcom@arm.com"
    )


def tidy_up_closed_issues(project_name, project_objs):
    """Delete project cards for all closed issues in the project.

    Args:
    project_name - GitHub project name
    project_objs - list of GitHub project objects

    """

    proj_obj = get_project_obj(project_name, project_objs)
    if proj_obj is None:
        userlog.error("Cannot get project object for %s", project_name)
        return

    column_objs = proj_obj.get_columns()

    card_match = False
    for column in column_objs:
        proj_cards = column.get_cards()

        for card in proj_cards:
            card_content = card.get_content()
            if card_content.state == "closed":

                userlog.info("Archiving project card for issue #%s from project:%s, column:%s", 
                    card_content.number, proj_obj.name, column.name)
                card.edit(archived=True)


def email_user(email, subject, body, from_address):
    """Send an email.

    Args:
    email - email address to send to
    subject - email subject
    body - email body
    from_address - email address (from)

    """
    message = Message(From=from_address, To=email)
    message.Subject = subject

    message.Html = body.encode("ascii", errors="replace")

    sender = Mailer("smtp.emea.arm.com")
    sender.send(message)


def main():

    arg_parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )

    help_issue = "GitHub token provided by a secret"
    arg_parser.add_argument(
        "-t",
        "--token",
        required=True,
        help=help_issue
    )

    args = arg_parser.parse_args()

    try:

        raise ValueError

        # Get GitHub access objects
        github_class = Github(LOGIN, str(args.token))

        repo, org = get_repo_and_org(github_class, GIT_ACCOUNT, REPO_NAME)

        with exit_on_exception("Cannot get organization projects for: ARMmbed"):
            project_objs = org.get_projects()

        userlog.info("Producing weekly report for %s", REPORT_REPO)
        produce_weekly_report(REPORT_REPO, REPORT_RECIPIENTS, project_objs)

        for proj_name in PROJECTS_TO_TIDY:
            tidy_up_closed_issues(proj_name, project_objs)


    except Exception:
        # Notify maintainers of bot exception.
        e = traceback.format_exc()
        userlog.exception(e)

        body = (
            """<p>THIS IS AN AUTOMATED EMAIL</p> <p>The Weekly automated"""
            """ script just failed with the following exception:</p> """
        )
        for line in e.splitlines():
            body += """<p>%s</p>""" % line

        body += """<p>If you are expecting to receive the weekly report """
        body += """note it may be delayed. Please contact the Mbed OS maintainers. </p>"""
        email_user(
            ["mbed-os-maintainers@arm.com", REPORT_RECIPIENTS],
            "Weekly Script FAILURE",
            body,
            "ciarmcom@arm.com"
        )


if __name__ == "__main__":
    main()
