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
# oss_git_to_jira.py
#
"""Configure newly created GitHub issues."""

import os
import sys
import argparse
import json
import logging
import netrc
import traceback
import subprocess
from time import sleep
from contextlib import contextmanager
from github import Github, GithubException
from mailer import Mailer
from mailer import Message
import pytz

userlog = logging.getLogger("Issues")

# Set logging level
userlog.setLevel(logging.DEBUG)

# Everything is output to the log file
logfile = os.path.join(os.getcwd(), "Issues.log")
log_file_handler = logging.FileHandler(logfile, mode="w")
log_file_handler.setLevel(logging.DEBUG)

# create console handler with a higher log level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter("%(name)s: %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
log_file_handler.setFormatter(formatter)

# add the handlers to the logger
userlog.addHandler(log_file_handler)
userlog.addHandler(console_handler)

GIT_ACCOUNT = "ARMmbed"
MIN_NUM_DESCRIPTION_WORDS = 25


class Github_backoff_error(Exception):
    """Backoff on Github error.

    @inherits Exception"""

    pass


class Command_retry_error(Exception):
    """Retry command on github interface error.

    @inherits Exception"""

    pass


@contextmanager
def exit_on_exception(text):
    """Log error and exits application on exception.

    @input exception text
    """
    try:
        yield
    except Exception as exc:
        userlog.error(text)
        userlog.exception(exc)
        sys.exit(1)


def run_cmd_with_retries(raise_exception, cmd, *argv, **kwargs):
    """Run an internally available command or method with retries.

    Executes the supplied command ('cmd') with the supplied arguments ('argv').
    If the command fails then the failure is logged and the command is retried.
    Up to 5 retries are available with a 30s delay between each.
    On successful completion the return from the called command is returned.
    If the command still fails after the max number of retries then a
    'Command_retry_error' exception is raised.

    Args:
    raise_exception - If True raise an exception after retries, else return exception
    cmd - internally available command or method to run
    argv - list of arguments to be passed to the command invocation
    kwargs - list of named arguments to be passed to the command invocation

    Returns:
    retval - return for the called cmd, or None
    exc - Exception text or None
    """
    retries = 5
    while True:
        try:
            userlog.info("Running command %s(%s, %s)", cmd, argv, kwargs)
            retval = cmd(*argv, **kwargs)
            break
        except (Exception, GithubException) as exc:
            userlog.error("Failed: %s", cmd)
            userlog.exception(exc)
            retries -= 1
            if retries == 0:
                if raise_exception:
                    raise Command_retry_error("Command failed after several retries")
                else:
                    return None, exc

            # Wait 30s before retrying the command
            sleep(30)

    return retval, None


def run_cmd_with_output(command, exit_on_failure=False):
    """Run a system command returning a status result and any command output.

    Passes a command to the system and returns a True/False result once the
    command has been executed, indicating success/failure. If the command was
    successful then the output from the command is returned to the caller.
    Commands are passed as a string.
    E.g. The command 'git remote -v' would be passed in as "git remote -v"

    Args:
    command - system command as a string
    exit_on_failure - If True exit the program on failure (default = False)

    Returns:
    return_code - True/False indicating the success/failure of the command
    output - The output of the command if it was successful, else empty string
    """
    text = "[Exec] " + command
    userlog.debug(text)
    returncode = 0
    output = ""
    try:
        output = subprocess.check_output(command, shell=True)
    except subprocess.CalledProcessError as error:
        text = (
                "The command "
                + str(command)
                + "failed with return code: "
                + str(error.returncode)
        )
        userlog.warning(text)
        returncode = error.returncode
        if exit_on_failure:
            sys.exit(1)
    return returncode, output


def ensure_available_rate_limits(github):
    """Check available GitHub requests.

    GitHub applies the following rate limiting:
    1. OAuth applications limited to 5000 requests per hour.
    2. Searches limited to 30 requests per minute

    This function will cause a back off for 30s if one of the following occurs:
    1. Standard requests have exceeded 90% of availablity
    2. Searches have exceeded 50% of availability

    Number of retries is set to 60 which would equate to 30 mins back off. If
    the limits have not recovered within this period then abort the script.
    Args: github - Main GitHub object
    """
    retries = 60
    notified = False
    raise_exception = True
    while True:
        limits, _ = run_cmd_with_retries(raise_exception, github.get_rate_limit)

        if limits.search.remaining >= (
                limits.search.limit / 2
        ) and limits.core.remaining >= (limits.core.limit / 10):
            break
        if not notified:
            userlog.info("Backing off due to GitHub rate limiting....")
            notified = True
        sleep(30)
        retries = retries - 1
        if retries == 0:
            raise Github_backoff_error("Command failed after several retries")


def get_labels(git_object, match=None):
    """Get the current labels for the specified git object.

         If the optional parameter 'match' is set then only labels containing the
         matching string will be returned

    Args:
    git_object - GitHub object using labels, can either be a repo, issue or PR object

    Returns:
    labels - set of matching label objects
    """
    raise_exception = True
    label_objects, _ = run_cmd_with_retries(raise_exception, git_object.get_labels)

    if match:
        labels = [label for label in label_objects if match in label.name]
    else:
        labels = label_objects

    return labels



def get_github_access():
    """Get an authenticated GitHub object.

    Reads the authentication credentials from the netrc file and uses them to
    obtain an authorized GitHub access object.

    Returns:
    github - GitHub object

    """
    home = os.environ["HOME"]
    netrc_file = os.path.join(home, ".netrc")
    with exit_on_exception("Cannot obtain authorization credentials."):
        auth = netrc.netrc(netrc_file)
        login, _, token = auth.authenticators("local")

    github = Github(str(login), str(token))

    return github


def get_git_repo(github, git_account, repo_name):
    """Get the repo object for the specified account and repo name.

    Args:
    github - GitHub object
    git_account - GitHub account
    repo_name - Repository to check for issues

    Returns:
    repo - Repository object for the specified repository name or None if the
           repo could not be found.

    """
    repo_path = git_account + "/" + repo_name
    raise_exception = False

    repo, exc = run_cmd_with_retries(raise_exception, github.get_repo, repo_path, False)

    if exc:
        userlog.error("**** Cannot access: %s ****", repo_path)
        userlog.error(exc)
        repo = None

    return repo


def get_newly_opened_github_issues(github, repo_name):
    """Return a list of GitHub issues that are open and not already mirrored.

    Args:
    github - GitHub object
    repo_name - Repository to check for open issues

    Returns:
    list of Github issues

    """

    # A new issue will have no priority label at all yet
    full_repo = "".join(["repo:", GIT_ACCOUNT, "/", repo_name])
    new_issue_filter = " ".join(
        [
            full_repo,
            "is:issue",
            "is:open",
            '-label:"priority: untriaged"',
            '-label:"priority: high"',
            '-label:"priority: medium"',
            '-label:"priority: community contribution"'
        ]
    )

    # Github search function requires the filter query as a string
    userlog.info("Running filter: '%s'", new_issue_filter)
    raise_exception = False
    new_open, exc = run_cmd_with_retries(
        raise_exception, github.search_issues, query=new_issue_filter
    )

    if exc:
        userlog.error("Could not read newly opened GitHub issues for %s", repo_name)
        return None

    return new_open


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

def parse_body(body):
    """Parse the header body of a GitHub issue.

    See https://github.com/ARMmbed/mbed-os/blob/master/.github/issue_template.md for
    issue format.

    Args:
    body - Issue header

    Returns:
    parsed - dictionary containing the body split into the individual sections
    """
    section = None
    in_guide = False

    # Initialise return dictionary
    parsed = dict(
        description=dict(text="", length=0),
        targets=dict(text="", length=0),
        toolchains=dict(text="", length=0),
        mbed_version=dict(text="", length=0),
        tools_versions=dict(text="", length=0),
        reproduction=dict(text="", length=0)
    )

    for line in body.splitlines():

        # Remove any leading whitespace at the start of the line
        line = line.lstrip()

        # Ignore guidance lines
        if line.startswith("<!--"):
            in_guide = True
            continue

        if line.startswith("-->"):
            in_guide = False
            continue

        if line.startswith("### Description of defect"):
            section = "description"
            continue

        if line.startswith("#### Target(s) affected by this defect"):
            section = "targets"
            continue

        if line.startswith("#### Toolchain(s) (name and version)"):
            section = "toolchains"
            continue

        if line.startswith("#### What version of Mbed-os"):
            section = "mbed_version"
            continue

        if line.startswith("#### What version(s) of tools"):
            section = "tools_versions"
            continue

        if line.startswith("#### How is this defect reproduced"):
            section = "reproduction"
            continue

        if section is not None and not in_guide:

            if len(line) > 0:
                parsed[section]["length"] += len(line.split(" "))
            parsed[section]["text"] += line + "\n"

    return parsed

def check_github_issue_template(github, parsed, issue, repo):
    """Check that all the fields in the new template have entries.

    If any data is missing a prompting comment is added to the PR
    Args:
    github - top level GitHub object
    parsed - dictionary containing entries for each template section
    issue - GitHub issue object
    repo - GitHub repository object

    Returns:
    True if the issue template contains sufficient information, False otherwise

    """
    header_new = "@%s thank you for raising this issue." % issue.user.login
    header_new += "Please take a look at the following comments:\n\n"

    added_prompt = ""

    if parsed["description"]["length"] < MIN_NUM_DESCRIPTION_WORDS:
        added_prompt += "Could you add some more detail to the description? "
        added_prompt += (
                "A good description should be at least %s words.\n"
                % MIN_NUM_DESCRIPTION_WORDS
        )

    if parsed["targets"]["length"] == 0:
        added_prompt += "What target(s) are you using?\n"

    if parsed["toolchains"]["length"] == 0:
        added_prompt += "What toolchain(s) are you using?\n"

    if parsed["mbed_version"]["length"] == 0:
        added_prompt += "What Mbed OS version are you using?\n"

    if parsed["tools_versions"]["length"] == 0:
        added_prompt += "It would help if you could also specify the versions of any " \
                        "tools you are using?\n "

    if parsed["reproduction"]["length"] == 0:
        added_prompt += "How can we reproduce your issue?\n"

    # Check if this issue has previously been parsed and found to have missing
    # information
    comments = issue.get_comments()

    # Check if we already have a template update request
    update_prompted = False

    for comment in comments:
        if header_new in comment.body:
            update_prompted = True
            userlog.info(
                "Found previous comment requesting template update:\n%s", comment.body
            )

    if added_prompt != "" and not update_prompted:

        # There is insufficient information provided for this issue thus publish the
        # comments.

        prompt = header_new
        userlog.info("Adding new template comment")

        prompt += added_prompt
        prompt += "\nNOTE: If there are fields which are not applicable then please " \
                  "just add 'n/a' or 'None'. "
        prompt += (
            "This indicates to us that at least all the fields have been considered."
        )
        prompt += "\nPlease update the issue header with the missing information. " 

        raise_exception = False
        _, exc = run_cmd_with_retries(raise_exception, issue.create_comment, prompt)

        if exc:
            userlog.error("Could not add comment to #%s", issue.number)

def process_issue_header(github, issue, repo):
    """Get the issue header and checks the description and issue type sections.

    Args: 
    github - top level GitHub object
    issue - issue object
    repo - GitHub repository object

    """
        
    # Read the issue body and break the template down into its 
    # constituent parts
    parsed = parse_body(issue.body)

    userlog.info(
        "Found the following template data for issue #%s:", 
        issue.number 
    )

    userlog.info("\tDescription: %s:", parsed["description"]["text"])
    userlog.info("\tTargets: %s:", parsed["targets"]["text"])
    userlog.info("\tToolchains: %s:", parsed["toolchains"]["text"])
    userlog.info("\tMbed Version: %s:", parsed["mbed_version"]["text"])
    userlog.info("\tTools/versions: %s:", parsed["tools_versions"]["text"])
    userlog.info("\tHow to reproduce: %s:", parsed["reproduction"]["text"])

    if parsed is not None:
        # Check conformance of the issue template

        check_github_issue_template(github, parsed, issue, repo)

    else:
        userlog.error(
            "Issue header could not be parsed."
        )

def main():

    arg_parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    help_config = "Path to the repository configuration file (default is 'repos.json')"
    arg_parser.add_argument(
        "-f",
        "--config_file",
        help=help_config,
        default=os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "config/repos.json"
        ),
        type=argparse.FileType("r")
    )
    help_issue = "Specify a repo/issue for testing new issue triaging. E.g. mbed-os:1200"
    arg_parser.add_argument(
        "-i",
        "--issue",
        help=help_issue
    )

    args = arg_parser.parse_args()

    # Top level exception handling
    try:

        # Get GitHub access objects
        github_class = get_github_access()

        if args.issue:
            userlog.info("Running in test mode using %s", args.issue)

            issue_parse = args.issue.split(":")

            userlog.info("Repo name = %s", issue_parse[0])
            userlog.info("Issue number = %s", issue_parse[1])

            repos = [
                {
                    "name" : issue_parse[0],
                    "template_verify" : True,
                    "nagbot_on" : True
                }
            ]

        else:

            # Load the config file
            config = json.load(args.config_file)

            if not config:
                text = "Failed to load config file: " + str(args.config_file)
                userlog.error(text)
                sys.exit(1)

            repos = config["repos"]

        with exit_on_exception("Cannot get organization for: ARMmbed"):
            org = github_class.get_organization("ARMmbed")

        workflow_start_col = None
        severity_start_col = None

        with exit_on_exception("Cannot get organization issue projects for: ARMmbed"):
            project_objs = org.get_projects()
            for proj_obj in project_objs:
                userlog.info("Project name: %s, Id: %s",proj_obj.name, proj_obj.id)

                column_objs = proj_obj.get_columns()
                userlog.info("\tColumns:")
                for column in column_objs:
                    userlog.info("\t\tName: %s, Id: %s", column.name, column.id)
                    if "Workflow" in proj_obj.name and "Needs Triage" in column.name:
                        workflow_start_col = column
                    if "Severity" in proj_obj.name and "Untriaged" in column.name:
                        severity_start_col = column

            if workflow_start_col is None or severity_start_col is None:
                raise ValueError


        for repo_obj in repos:

            # Add small delay to stop GitHub hitting the 30 search requests per min
            # rate limit
            sleep(10)

            repo_name = repo_obj["name"]
            repo = get_git_repo(github_class, GIT_ACCOUNT, repo_name)

            if repo:

                if args.issue:

                    test_issue = repo.get_issue(int(issue_parse[1]))
                    new_issues = [test_issue]

                else:
                    new_issues = get_newly_opened_github_issues(github_class, repo_name)

                userlog.info("New issues:")
                for issue in new_issues:
                    userlog.info("\tTitle: %s, Num: %s", issue.title, issue.number)

                    # Add project cards for this issue
                    workflow_start_col.create_card(content_id = issue.id, content_type = "Issue")
                    severity_start_col.create_card(content_id = issue.id, content_type = "Issue")

                    # Add priority untriaged label
                    issue.add_to_labels("priority: untriaged")

                    # Set component to Untriaged
                    issue.add_to_labels("component: untriaged")

                    # Now validate issue header and comment if required
                    if repo_obj["template_verify"]:
                        process_issue_header(github_class, issue, repo)

    except Exception:
        # Notify maintainers of bot exception.
        err = traceback.format_exc()
        userlog.exception(err)

        body = """<p>THIS IS AN AUTOMATED EMAIL</p> <p>The issue triaging automated""" \
               """ script just failed with the following exception:</p> """
        for line in err.splitlines():
            body += """<p>%s</p>""" % line
        body += """Please check the latest log file for further details.</p>"""
        email_user(
            "mbed-os-maintainers@arm.com",
            "Issue triaging  Script FAILURE",
            body,
            "ciarmcom@arm.com"
        )

if __name__ == "__main__":
    main()
