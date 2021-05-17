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
import subprocess
from time import sleep
from contextlib import contextmanager
from github import Github, GithubException

GIT_ACCOUNT = "ARMmbed"
LOGIN = "adbridge"
MIN_NUM_DESCRIPTION_WORDS = 25

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
        print(error(text))
        print(exception(exc))
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
            retval = cmd(*argv, **kwargs)
            break
        except (Exception, GithubException) as exc:
            print(exception(exc))
            retries -= 1
            if retries == 0:
                if raise_exception:
                    raise Command_retry_error("Command failed after several retries")
                else:
                    return None, exc

            # Wait 30s before retrying the command
            sleep(30)

    return retval, None

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
        print("**** Cannot access: repo path ****")
        print(error(exc))
        repo = None

    return repo


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
    help_issue = "Specify an issue number for new issue triaging. E.g. 1200"
    arg_parser.add_argument(
        "-i",
        "--issue",
        required=True,
        help=help_issue
    )

    help_issue = "Specify a repo name for new issue triaging. E.g. mbed-os"
    arg_parser.add_argument(
        "-r",
        "--repo",
        required=True,
        help=help_issue
    )

    help_issue = "GitHub token provided by a secret"
    arg_parser.add_argument(
        "-t",
        "--token",
        required=True,
        help=help_issue
    )

    args = arg_parser.parse_args()

    repo_name = args.repo
    issue_num = args.issue

#    token = os.environ['ISSUE_TOKEN']

    print("Running....")

    # Get GitHub access objects
    github_class = Github(LOGIN, str(args.token))

    with exit_on_exception("Cannot get organization for: ARMmbed"):
        org = github_class.get_organization("ARMmbed")

    workflow_start_col = None
    severity_start_col = None

    with exit_on_exception("Cannot get organization issue projects for: ARMmbed"):
        project_objs = org.get_projects()
        for proj_obj in project_objs:

            column_objs = proj_obj.get_columns()
            for column in column_objs:
                if "Workflow" in proj_obj.name and "Needs Triage" in column.name:
                    workflow_start_col = column
                if "Severity" in proj_obj.name and "Untriaged" in column.name:
                    severity_start_col = column

        if workflow_start_col is None or severity_start_col is None:
            raise ValueError

        repo_obj = get_git_repo(github_class, GIT_ACCOUNT, repo_name)

        if repo_obj:

            issue_obj = repo_obj.get_issue(int(issue_num))

            # Add project cards for this issue
            workflow_start_col.create_card(content_id = issue_obj.id, content_type = "Issue")
            severity_start_col.create_card(content_id = issue_obj.id, content_type = "Issue")

            # Add priority untriaged label
            issue_obj.add_to_labels("priority: untriaged")

            # Set component to Untriaged
            issue_obj.add_to_labels("component: untriaged")

            # Now validate issue header and comment if required
            process_issue_header(github_class, issue_obj, repo_obj)


if __name__ == "__main__":
    main()
