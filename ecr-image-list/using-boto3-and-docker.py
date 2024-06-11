#!/usr/bin/env python3

### IMPORTS ###
import argparse
import datetime
import logging
import os
import subprocess

import boto3

### GLOBALS ###

### FUNCTIONS ###
def get_ecr_images_newer_than(ecr_client, repo_name, newer_than):
    result = []

    batch_count = 0
    total_count = 0
    image_count = 0
    nextToken = {}
    while True:
        response = ecr_client.describe_images(repositoryName = repo_name, **nextToken)
        batch_count = batch_count + 1
        for entry in response["imageDetails"]:
            total_count = total_count + 1
            if entry["imagePushedAt"].strftime("%Y-%m-%d") >= newer_than:
                image_count = image_count + 1
                for tag in entry["imageTags"]:
                    result.append("{}:{}".format(entry["repositoryName"], tag))
        if "nextToken" in response:
            nextToken = { "nextToken": response["nextToken"] }
        else:
            # No "nextToken", so at the end of the processing
            break
    logging.info("Batch Count: %d, Total Count: %d, Image Count: %d", batch_count, total_count, image_count)
    logging.debug("Images found: %s", result)

    return result

def docker_login(login_data):
    logging.debug("Logging into Docker CLI")
    tmp_prep_cmd = "docker login -u {} -p {} {}".format(
        login_data['user'],
        login_data['apikey'],
        login_data['docker_remote_url']
    )
    logging.debug("  tmp_prep_cmd: %s", tmp_prep_cmd)
    tmp_prep_output = subprocess.run(
        tmp_prep_cmd.split(' '), stdout = subprocess.PIPE, stderr = subprocess.PIPE
    )
    if tmp_prep_output.returncode == 0:
        logging.debug("  Successfully logged into docker")
    else:
        logging.warning("Failed to log into docker: %s", tmp_prep_output.stderr)

def docker_pull_image(login_data, image_name_tag):
    logging.debug("Pulling the docker image: %s/%s", login_data['docker_remote_url'], image_name_tag)
    tmp_pull_cmd = "docker pull {}/{}".format(login_data['docker_remote_url'], image_name_tag)
    tmp_pull_output = subprocess.run(tmp_pull_cmd.split(' '), stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    logging.debug("  tmp_pull_output: %s", tmp_pull_output)
    if tmp_pull_output.returncode == 0:
        logging.debug("  Successfully pulled '%s/%s'", login_data['docker_remote_url'], image_name_tag)
    else:
        logging.warning("Failed to pull image '%s/%s' with error: %s", login_data['docker_remote_url'], image_name_tag, tmp_pull_output.stderr)

### CLASSES ###

### MAIN ###
def main():
    parser_description = """
    Pulls a list of ECR images newer than a day ago, then pulls them from a JFrog Artifactory remote repository.
    
    NOTE: AWS credentials must be setup before running this script (e.g. `aws configure`).
    """

    parser = argparse.ArgumentParser(description = parser_description, formatter_class = argparse.RawTextHelpFormatter)
    parser.add_argument("-v", "--verbose", action = "store_true")

    parser.add_argument("--user", default = os.getenv("ARTIFACTORY_USER", ""),
                        help = "Artifactory user to use for requests.  Will use ARTIFACTORY_USER if not specified.")
    parser.add_argument("--apikey", default = os.getenv("int_artifactory_accessToken", ""),
                        help = "Artifactory apikey to use for requests.  Will use 'int_artifactory_accessToken' if not specified.")
    parser.add_argument("--host", default = os.getenv("int_artifactory_url", ""),
                        help = "Artifactory host URL (e.g. https://artifactory.example.com/) to use for requests.  Will use 'int_artifactory_url' if not specified.")

    parser.add_argument("--remote-repo", default = os.getenv("REMOTE_REPO"),
                        help = "The name of the Artifactory remote repository that is pointed to the ECR repository.")

    parser.add_argument("--aws-profile", default = "default",
                        help = "The profile used for AWS authentication.")

    parser.add_argument("--days-to-pull", default = 1, type = int,
                        help = "The number of days of recent images to pull.")

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        format = "%(asctime)s:%(levelname)s:%(name)s:%(funcName)s: %(message)s",
        level = logging.DEBUG if args.verbose else logging.INFO
    )
    logging.debug("Args: %s", args)

    # Prepare the Environment
    logging.info("Preparing Environment")
    tmp_login_data = {
        "user": args.user,
        "apikey": args.apikey,
        "host": args.host
    }
    # FIXME: Not the nicest way to make this URL
    remote_repo_name = args.remote_repo
    tmp_login_data['docker_url'] = str(tmp_login_data['host'].split('/')[2])
    tmp_login_data['docker_remote_url'] = "{}/{}".format(tmp_login_data['docker_url'], remote_repo_name)
    logging.info("  Artifactory Host: %s", tmp_login_data["host"])
    logging.info("  Artifactory User: %s", tmp_login_data["user"])
    logging.info("  Remote Repository: %s", remote_repo_name)
    logging.info("  Docker Remote URL: %s", tmp_login_data['docker_remote_url'])
    docker_login(tmp_login_data)
    aws_ecr_client = boto3.session.Session(profile_name = args.aws_profile).client("ecr") # Region needed here?

    # Getting the image list
    newer_than = datetime.datetime.now() - datetime.timedelta(days = args.days_to_pull)
    name_tags_to_pull = get_ecr_images_newer_than(aws_ecr_client, remote_repo_name, newer_than)

    # Pulling each of the images
    for name_tag in name_tags_to_pull:
        docker_pull_image(tmp_login_data, name_tag)

if __name__ == "__main__":
    main()
