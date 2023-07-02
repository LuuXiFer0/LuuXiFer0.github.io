# Welcome to BGSV Code Race 2023 - Round 2
## Introduction
* CI/CD pipeline allows faster development and deployment of software application.​
* Given a standard CI/CD pipeline in DevOps including building and testing software application.​
* Mentors shall give a C/C++ or Python program with some vulnerabilities.​
* The contestants are **required** to​
    * Investigate security tools including static vulnerability scanning and fuzzing to help the detection of vulnerabilities.​
    * Extend the given pipeline and integrate security tools.​
    * Make the findings from security tools user-friendly.

## Something nice to have
* Local linux OS, it can be virtual machine on Window or you have your own linux laptop. Then
you don't need to wait for the pipeline to test your tool or code since the pipeline is also linux.

## Scoring Criteria
* Be able to detect the vulnerabilities in the given program.​
* Be able to visualize the report from security toolings.​
* Be able to fix the vulnerabilities.​
* (Extra) Polish the presentation of the pipeline.

## Submission
* You can write a README.md in your branch to describe everything you do.
* Or you can write it in Word.

## Mentor/advisor responsibilities
* Should NOT
    * Tell them what tools to use for security scanning tools and fuzz testing.
    * Tell them how to fix, let them do it.
* Should
    * Advise on the GUI or UX of the pipeline i.e. break down stages, summary of errors/findings reported from the tool.
    * Elaborate the errors/findings to the contestants.
    * Be a critical thinker, using your questions to guide them on choosing the right tool.
* Must
    * Support you on accessing the pipeline i.e. snapshot the image of the pipeline or log.

## Let's start
* Your Python program shall be placed in src directory.
* Create your team branch from main branch. Name the branch with your team name.
* The pipeline shall be created once you open the Pull Request.
* .pipelines/pr_develop.yaml contains stages in the pipeline.

