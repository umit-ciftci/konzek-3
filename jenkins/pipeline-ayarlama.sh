
 - Go to the Jenkins dashboard and click on `New Item` to create a pipeline.

 - Enter `CI/CD-pipeline` then select `Pipeline` and click `OK`.

- Pipeline:
    Definition: Pipeline script from SCM
    SCM: Git
      Repositories:
        - Repository URL: https://github.com/umit-ciftci/konzek-3.git
        - Branches to build: 
            Branch Specifier: */main

    Script Path: Jenkinsfile 