# Nuclei Templates

In this directory you can find a template to detect an Apache StreamPipes installation and another one to verify if it's vulnerable to CVE-2024-29868.

-   `apache-streampipes-detect.yaml`: template to detect Apache StreamPipes installations.
    Checks for the presence of "apache streampipes" in the body of the base url and in `{{BaseURL}}/streampipes-backend/api/openapi.json`. Then, it checks for the hash of the favicon in `{{BaseURL}}/assets/img/favicon/favicon.ico` path.
-   `CVE-2024-29868.yaml`: template to identify CVE-2024-29868 vulnerability. First, it checks if the right conditions are met (both `allowPasswordRecovery` and `allowSelfRegistration` are set to `true`). Then, it checks if the version detected is included in the vulnerable ones (version `0.69.0` through `0.93.0`). If both conditions are met then a warning is displayed.
    ![CVE-2024-29868-template-output](/detection/img/01-Template_output.png)
