from __future__ import print_function
import sys
import boto3
import os
import urllib
import zipfile
import json
import time
import hmac
import base64
import hashlib
from botocore.client import Config

code_pipeline = boto3.client('codepipeline')

def put_job_success(job, message):
    print('Putting job success')
    print(message)
    code_pipeline.put_job_success_result(jobId=job)


def put_job_failure(job, message):
    print('Putting job failure')
    print(message)
    code_pipeline.put_job_failure_result(jobId=job, failureDetails={'message': message, 'type': 'JobFailed'})


def handler(event, context):

    job_id = event['CodePipeline.job']['id']
    job_data = event['CodePipeline.job']['data']

    # create a session based on the STS credentails from CodePipeline
    s3 = boto3.client(
        's3',
        aws_access_key_id=job_data['artifactCredentials']['accessKeyId'],
        aws_secret_access_key=job_data['artifactCredentials']['secretAccessKey'],
        aws_session_token=job_data['artifactCredentials']['sessionToken'],
        config=Config(signature_version='s3v4')
    )

    # grab the credentials for CloudSploit
    api_key = os.environ['cloudsploit_key']
    secret = os.environ['cloudsploit_secret']

    # extract our template to disk and load it
    bucket = job_data['inputArtifacts'][0]['location']['s3Location']['bucketName']
    key = job_data['inputArtifacts'][0]['location']['s3Location']['objectKey']

    s3.download_file(bucket, key, '/tmp/target.zip')
    with zipfile.ZipFile('/tmp/target.zip', 'r') as zip_ref:
        zip_ref.extractall('/tmp')

    # prepare the payload to send to CloudSploit
    endpoint = 'https://api.cloudsploit.com'
    path = '/v2/cloudformations'
    method = 'POST'
    timestamp = str(int(time.time() * 1000))

    with open('/tmp/template.yaml', 'r') as yaml_file:
        file_content = yaml_file.read()

    yaml_base64 = base64.b64encode(file_content.encode('utf-8')).decode('utf-8')

    body = { "base64": yaml_base64 }
    body_str = json.dumps(body, separators=(',', ':'))

    message = timestamp + method + path + body_str
    signature = hmac.new(secret.encode('utf-8'), msg=message.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()

    headers = {
        'accept': 'application/json',
        'x-api-key': api_key,
        'x-signature': signature,
        'x-timestamp': timestamp,
        'content-type': 'application/json'
    }

    # do the request
    request = urllib.request.Request(endpoint + path, data=body_str.encode('utf-8'), headers=headers)

    # grab any messages from the response
    response = urllib.request.urlopen(request).read();
    messages = json.loads(response.decode('utf-8'))['data']

    # check for error messages and properly callback to CodePipeline
    error_found = False
    for message in messages:
        if(message['status'] > 0):
            error_found = True
            print("Error '" + message['message'] + "' for resource '" + message['resource'] + "'")

    if(error_found):
        put_job_failure(job_id, 'Failure')
    else:
        put_job_success(job_id, 'Success')
