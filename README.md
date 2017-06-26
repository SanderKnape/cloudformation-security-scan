# CloudSploit security scan in Lambda
The AWS Lambda function in this repository is an example for running a [CloudSploit](https://www.cloudsploit.com) security scan using Python 3. Instead of the more regular `requests` module, I use the built-in `urllib` module so this function can be run without additional dependencies.

This function is part of a blogpost I wrote: [Use Infrastructure as Code for automated security in the deployment pipeline](https://sanderknape.com/2017/06/improving-your-security-with-infrastructure-as-code).
