# CVE-2023-1177 (MLFlow Path Traversal) #
### About MLflow

MLflow is an open-source platform for managing the end-to-end machine learning lifecycle.

**Primary Functions:**

*MLflow tackles four primary functions:*

Tracking experiments to record and compare parameters and results (MLflow Tracking).

Packaging ML code in a reusable, reproducible form in order to share with other data scientists or transfer to production (MLflow Projects).

Managing and deploying models from a variety of ML libraries to a variety of model serving and inference platforms (MLflow Models).

Providing a central model store to collaboratively manage the full lifecycle of an MLflow Model, including model versioning, stage transitions, and annotations (MLflow Model Registry).

**Library-Agnostic:** MLflow is library-agnostic, meaning it can be used with any machine learning library and in any programming language since all functions are accessible through a REST API and CLI.

**API:** The project includes a Python API, R API, and Java API for convenience.

Source: https://mlflow.org/docs/latest/index.html

### CVE-2023-1177

A path traversa vulnerability was found in the MLflow. 
Path traversal is a type of web vulnerability that allows an attacker to access files and directories stored outside the intended directory. Attackers use various techniques to exploit this vulnerability and gain unauthorized access to sensitive data or execute arbitrary code. Path traversal attacks can be prevented by input validation and access control measures

The vulnerability is discovered by **[Dan McInerney](https://github.com/DanMcInerney/)**.

**Read More:** https://huntr.dev/bounties/1fe8f21a-c438-4cba-9add-e8a5dab94e28/

**[CVE-2023-1177]**

*Path Traversal: '..\filename' in GitHub repository mlflow/mlflow prior to 2.2.1.*

**Read more:** https://nvd.nist.gov/vuln/detail/CVE-2023-1177

### PoC for CVE-2023-1177
I've created a small Python script that can be used to test and exploit the vulnerability

It will create a unique ID for the model name and then access all the URLs in consecutive order.


![alt text](PoC-CVE-2023-1177.png)
