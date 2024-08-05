import json
import logging
import os
import urllib.parse
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import formataddr, parseaddr

import boto3
from botocore.exceptions import ClientError

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set up AWS clients
s3_client = boto3.client("s3")
ses_client = boto3.client("ses", region_name="ap-northeast-1")

CHARSET = "utf-8"
SENDER_EMAIL_DOMAIN = "example.com"
DEFAULT_RECIPIENTS = ["default@gmail.com"]


def load_forwarding_rules():
    with open("forward_config.json", "r") as f:
        return json.load(f)


FORWARDING_RULES = load_forwarding_rules()
# Environment variables
PRIVATE_BUCKET_NAME = os.environ["BUCKET_NAME"]


def lambda_handler(event, context):

    # Log the full event
    logger.info("Received event: %s", event)

    # Parse S3 event and decode key
    encoded_key = event["Records"][0]["s3"]["object"]["key"]
    decoded_key = urllib.parse.unquote_plus(encoded_key)

    logger.info("Decoded key: %s", decoded_key)
    logger.info("Encoded key: %s", encoded_key)

    try:
        # Read email content from S3
        response = s3_client.get_object(Bucket=PRIVATE_BUCKET_NAME, Key=decoded_key)
        raw_email = response["Body"].read()

        # Parse the .eml file
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)

        # Extract original sender
        original_sender_header = msg["From"]
        original_sender_name, original_sender_email = parseaddr(original_sender_header)

        logger.info("Original sender name: %s", original_sender_name)
        logger.info("Original sender email: %s", original_sender_email)

        if not original_sender_name:
            display_name = original_sender_email
        else:
            display_name = original_sender_name

        # Extract recipient address
        to_address = msg["To"]
        if isinstance(to_address, str):
            to_address = to_address.lower().strip()
        else:
            decoded_to_address = decode_header(str(to_address))
            to_address = ""
            for header in decoded_to_address:
                if isinstance(header[0], bytes):
                    to_address += header[0].decode(header[1] or "utf-8")
                else:
                    to_address += header[0]
            to_address = to_address.lower().strip()

        # Determine forwarding rules
        forwarding_rule = FORWARDING_RULES.get(to_address, None)

        if forwarding_rule:
            recipient_emails = forwarding_rule["recipients"]
            sender_local_part = forwarding_rule["sender_local_part"]
        else:
            recipient_emails = DEFAULT_RECIPIENTS
            sender_local_part = to_address.split("@")[
                0
            ]  # Use the local part of the address

        sender_email = f"{sender_local_part}@{SENDER_EMAIL_DOMAIN}"

        # Ensure From uses our domain
        from_address = sender_email

        # Modify the original email's From and To headers
        if msg.get("From"):
            msg.replace_header("From", formataddr((display_name, from_address)))
        else:
            msg["From"] = formataddr((display_name, from_address))

        if msg.get("To"):
            msg.replace_header("To", ", ".join(recipient_emails))
        else:
            msg["To"] = ", ".join(recipient_emails)

        # Add Reply-To header
        msg.add_header("Reply-To", original_sender_email)

        # Remove unnecessary headers
        if msg.get("Return-Path"):
            del msg["Return-Path"]
        if msg.get("Sender"):
            del msg["Sender"]
        if msg.get("Message-ID"):
            del msg["Message-ID"]
        while msg.get("DKIM-Signature"):
            del msg["DKIM-Signature"]

        # Construct new raw email content
        raw_email = msg.as_bytes()

        # Forward the email using SES
        logger.info("Attempting to send email via SES...")
        response = ses_client.send_raw_email(
            Source=from_address,
            Destinations=recipient_emails,
            RawMessage={"Data": raw_email},
        )
        logger.info("SES response: %s", response)

        logger.info("Email forwarded successfully")
        return {"statusCode": 200, "body": "Email forwarded successfully"}

    except s3_client.exceptions.NoSuchKey as e:
        logger.error(
            "NoSuchKey error: The specified key %s does not exist.", decoded_key
        )
        logger.error("Exception: %s", str(e))
        return {
            "statusCode": 404,
            "body": f"Failed to retrieve the object {decoded_key} from bucket {PRIVATE_BUCKET_NAME}.",
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error("ClientError: %s - %s", error_code, error_message)
        return {
            "statusCode": 500,
            "body": f"Client error occurred: {error_code} - {error_message}",
        }

    except Exception as e:
        logger.error("General error: %s", str(e))
        return {
            "statusCode": 500,
            "body": "An error occurred while processing the email.",
        }
