pipeline {
    agent any {
    customWorkspace '/application/php-frontend'
    }
    environment {
        // Application Configuration
        APP_NAME = '-php-frontend'
        DOCKER_IMAGE = 'php-frontend'
        
        // AWS Configuration
        AWS_ACCOUNT_ID = '699951450237'
        AWS_REGION = 'ap-south-1'
        ECR_REPO = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/rspl-sandbox-ecr/${DOCKER_IMAGE}"
        
        // Tool Configuration
        SONARQUBE_URL = 'https://sonarqube.retailershakti.com'
        SONARQUBE_TOKEN = credentials('sonarqube-token')
        ARGOCD_SERVER = 'https://argocd-sandbox.retailershakti.com'
        ARGOCD_TOKEN = credentials('argocd-token')
        
        // Notification Configuration
        SLACK_CHANNEL = '#pipeline-notifications'
        SLACK_TOKEN = credentials('slack-jenkins-token')
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                slackSend(channel: SLACK_CHANNEL, color: 'good', message: "✅ ${env.JOB_NAME} #${env.BUILD_NUMBER}: Checkout completed successfully")
            }
        }
        
        stage('PHP Lint Check') {
            steps {
                script {
                    try {
                        // Install composer dependencies without dev
                        sh 'composer install'
                        sh 'composer dump-autoload'

                        // Run PHP Code Sniffer, PHP Mess Detector, PHPStan as before
                        sh '''
                            ./vendor/bin/phpcs --standard=PSR2 app/src/
                            ./vendor/bin/phpcbf --standard=PSR2 app/src/
                            ./vendor/bin/phpmd app/src/ text codesize,unusedcode,naming
                            ./vendor/bin/phpstan analyse app/src/ --level=5
                        '''

                        // Run PHP lint check and capture output/errors
                        def lintOutput = sh(script: 'find app/src/ -type f -name "*.php" -print0 | xargs -0 -n1 php -l', returnStdout: true).trim()

                        // Check if there are any lint errors in the output
                        if (lintOutput.contains("Errors parsing")) {
                            echo "PHP lint errors found:\n${lintOutput}"
                            slackSend(channel: SLACK_CHANNEL, color: 'danger', message: "❌ ${env.JOB_NAME} #${env.BUILD_NUMBER}: PHP lint check failed\n```" + lintOutput + "```")
                            error "PHP lint check failed"
                        } else {
                            echo "PHP lint passed:\n${lintOutput}"
                            slackSend(channel: SLACK_CHANNEL, color: 'good', message: "✅ ${env.JOB_NAME} #${env.BUILD_NUMBER}: PHP lint check passed")
                        }
                    } catch (err) {
                        // Catch any unexpected error
                        slackSend(channel: SLACK_CHANNEL, color: 'danger', message: "❌ ${env.JOB_NAME} #${env.BUILD_NUMBER}: PHP lint check failed with error: ${err}")
                        error "PHP lint check failed with exception"
                    }
                }
            }
        }

        stage('Composer Unit Tests') {
            steps {
                script {
                    try {
                        sh '''
                        echo "Running PHPUnit tests..."
                        mkdir -p reports
                        ./vendor/bin/phpunit --configuration phpunit.xml --log-junit reports/phpunit.xml --coverage-clover reports/coverage.xml
                        '''
                        slackSend(channel: SLACK_CHANNEL, color: 'good', message: "✅ ${env.JOB_NAME} #${env.BUILD_NUMBER}: PHPUnit tests passed")
                    } catch (e) {
                        slackSend(channel: SLACK_CHANNEL, color: 'danger', message: "❌ ${env.JOB_NAME} #${env.BUILD_NUMBER}: PHPUnit tests failed")
                        error "PHPUnit tests failed"
                    }
                }
            }
        }

        stage('PHPStan Analyse') {
            steps {
                script {
                    try {
                        sh '''
                        echo "Running PHPStan analyse..."
                        ./vendor/bin/phpstan analyse app/src/ --level=5 --error-format=checkstyle > reports/phpstan-checkstyle.xml || true
                        '''
                        slackSend(channel: SLACK_CHANNEL, color: 'good', message: "✅ ${env.JOB_NAME} #${env.BUILD_NUMBER}: PHPStan analyse completed")
                    } catch (e) {
                        slackSend(channel: SLACK_CHANNEL, color: 'danger', message: "❌ ${env.JOB_NAME} #${env.BUILD_NUMBER}: PHPStan analyse failed")
                        error "PHPStan analyse failed"
                    }
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                script {
                    try {
                        // Run SonarQube analysis
                        withSonarQubeEnv('sonarqube.retailershakti.com') {
                            sh """
                            sonar-scanner \
                                -Dsonar.projectKey=${APP_NAME} \
                                -Dsonar.sources=app/src \
                                -Dsonar.host.url=${SONARQUBE_URL} \
                                -Dsonar.login=${SONARQUBE_TOKEN} \
                                -Dsonar.projectVersion=${env.BUILD_NUMBER} \
                                -Dsonar.php.coverage.reportPaths=reports/coverage.xml \
                                -Dsonar.php.tests.reportPath=reports/phpunit.xml \
                                -Dsonar.phpstan.reportPath=reports/phpstan-checkstyle.xml \
                                -Dsonar.junit.reportPaths=reports/phpunit.xml

                            """
                        }
                        
                        // Get the project URL from the scanner output
                        def sonarReportUrl = sh(
                            script: "grep -o 'ANALYSIS SUCCESSFUL, you can browse .*' sonar-reports/.scannerwork/report-task.txt | cut -d' ' -f6",
                            returnStdout: true
                        ).trim()
                        
                        // Get quality gate status
                        def qualityGateStatus = sh(
                            script: """
                            curl -s -u ${SONARQUBE_TOKEN}: \
                            "${SONARQUBE_URL}/api/qualitygates/project_status?projectKey=${APP_NAME}" | \
                            jq -r '.projectStatus.status'
                            """,
                            returnStdout: true
                        ).trim()
                        
                        // Get summary metrics
                        def metrics = sh(
                            script: """
                            curl -s -u ${SONARQUBE_TOKEN}: \
                            "${SONARQUBE_URL}/api/measures/component?component=${APP_NAME}&metricKeys=bugs,vulnerabilities,code_smells,coverage,duplicated_lines_density" | \
                            jq -r '.component.measures[] | .metric + ": " + .value'
                            """,
                            returnStdout: true
                        ).trim()
                        
                        // Format Slack message
                        def color = qualityGateStatus == 'OK' ? 'good' : 'danger'
                        def statusEmoji = qualityGateStatus == 'OK' ? '✅' : '❌'
                        
                        def slackMessage = """
                        ${statusEmoji} *SonarQube Analysis Complete* - ${env.JOB_NAME} #${env.BUILD_NUMBER}
                        *Quality Gate Status:* ${qualityGateStatus}
                        *Report URL:* ${sonarReportUrl}
                        *Metrics:*
                        ${metrics}
                        """
                        
                        // Send to Slack
                        slackSend(
                            channel: SLACK_CHANNEL,
                            color: color,
                            message: slackMessage,
                            failOnError: false
                        )
                        
                        // Fail the build if quality gate fails
                        if (qualityGateStatus != 'OK') {
                            error "SonarQube Quality Gate failed with status: ${qualityGateStatus}"
                        }
                        
                    } catch (e) {
                        slackSend(
                            channel: SLACK_CHANNEL,
                            color: 'danger',
                            message: "❌ ${env.JOB_NAME} #${env.BUILD_NUMBER}: SonarQube analysis failed\nError: ${e.message}",
                            failOnError: false
                        )
                        error "SonarQube analysis failed"
                    }
                }
            }
        }
        
        stage('Trivy Filesystem Scan') {
            steps {
                script {
                    try {
                        // Run Trivy scan and output to JSON
                        sh '''
                        echo "Running Trivy filesystem scan..."
                        trivy fs --security-checks vuln,config,secret --severity CRITICAL,HIGH --format json --output reports/trivy-fs-report.json app/
                        '''
                        
                        // Parse the JSON report
                        def trivyReport = readJSON file: 'reports/trivy-fs-report.json'
                        def criticalCount = 0
                        def highCount = 0
                        def findings = []
                        
                        trivyReport.Results.each { result ->
                            result.Vulnerabilities.each { vuln ->
                                if (vuln.Severity == "CRITICAL") criticalCount++
                                if (vuln.Severity == "HIGH") highCount++
                                findings << "${vuln.Severity}: ${vuln.VulnerabilityID} - ${vuln.Title}"
                            }
                        }
                        
                        // Format Slack message
                        def color = (criticalCount + highCount) > 0 ? 'danger' : 'good'
                        def statusEmoji = (criticalCount + highCount) > 0 ? '❌' : '✅'
                        
                        def slackMessage = """
                        ${statusEmoji} *Trivy Filesystem Scan Results* - ${env.JOB_NAME} #${env.BUILD_NUMBER}
                        *Critical Findings:* ${criticalCount}
                        *High Findings:* ${highCount}
                        *Scan Target:* app/
                        """
                        
                        // Add sample findings if any
                        if (findings) {
                            slackMessage += "*Sample Findings:*\n${findings.take(5).join('\n')}"
                            if (findings.size() > 5) {
                                slackMessage += "\n_+ ${findings.size() - 5} more findings..._"
                            }
                        }
                        
                        // Send to Slack
                        slackSend(
                            channel: SLACK_CHANNEL, 
                            color: color,
                            message: slackMessage,
                            failOnError: false
                        )
                        
                        // Also upload the full report
                        slackUploadFile(
                            channel: SLACK_CHANNEL,
                            filePath: 'reports/trivy-fs-report.json',
                            initialComment: "Full Trivy Filesystem Scan Report"
                        )
                        
                        // Fail if critical findings
                        if (criticalCount > 0) {
                            error "Trivy found ${criticalCount} critical vulnerabilities"
                        }
                        
                    } catch (e) {
                        slackSend(
                            channel: SLACK_CHANNEL, 
                            color: 'danger',
                            message: "❌ ${env.JOB_NAME} #${env.BUILD_NUMBER}: Trivy filesystem scan failed\nError: ${e.message}",
                            failOnError: false
                        )
                        error "Trivy filesystem scan failed"
                    }
                }
            }
        }
        
        stage('OWASP Dependency Check') {
            steps {
                script {
                    try {
                        // Run dependency check
                        sh '''
                        echo "Running OWASP Dependency Check..."
                        dependency-check.sh --scan app --format HTML --format JSON --format XML --out reports/ --project ${APP_NAME}
                        '''
                        
                        // Parse the JSON report
                        def owaspReport = readJSON file: 'reports/dependency-check-report.json'
                        def criticalCount = 0
                        def highCount = 0
                        def dependencies = [:]
                        
                        owaspReport.dependencies.each { dep ->
                            dep.vulnerabilities?.each { vuln ->
                                if (vuln.severity == "Critical") criticalCount++
                                if (vuln.severity == "High") highCount++
                                
                                if (!dependencies.containsKey(dep.fileName)) {
                                    dependencies[dep.fileName] = []
                                }
                                dependencies[dep.fileName] << "${vuln.severity}: ${vuln.name} (CVSS: ${vuln.cvssv3?.baseScore ?: vuln.cvssv2?.score})"
                            }
                        }
                        
                        // Format Slack message
                        def color = (criticalCount + highCount) > 0 ? 'danger' : 'good'
                        def statusEmoji = (criticalCount + highCount) > 0 ? '❌' : '✅'
                        
                        def slackMessage = """
                        ${statusEmoji} *OWASP Dependency Check Results* - ${env.JOB_NAME} #${env.BUILD_NUMBER}
                        *Critical Vulnerabilities:* ${criticalCount}
                        *High Vulnerabilities:* ${highCount}
                        *Scanned Dependencies:* ${owaspReport.dependencies.size()}
                        """
                        
                        // Add sample vulnerable dependencies if any
                        if (dependencies) {
                            slackMessage += "*Vulnerable Dependencies:*\n"
                            dependencies.each { dep, vulns ->
                                if (vulns.any { it.contains('Critical') || it.contains('High') }) {
                                    slackMessage += "• ${dep}:\n  - ${vulns.take(2).join('\n  - ')}\n"
                                }
                            }
                        }
                        
                        // Send to Slack
                        slackSend(
                            channel: SLACK_CHANNEL, 
                            color: color,
                            message: slackMessage,
                            failOnError: false
                        )
                        
                        // Also upload HTML report
                        slackUploadFile(
                            channel: SLACK_CHANNEL,
                            filePath: 'reports/dependency-check-report.html',
                            initialComment: "Full OWASP Dependency Check Report"
                        )
                        
                        // Fail if critical findings
                        if (criticalCount > 0) {
                            error "OWASP found ${criticalCount} critical vulnerabilities"
                        }
                        
                    } catch (e) {
                        slackSend(
                            channel: SLACK_CHANNEL, 
                            color: 'danger',
                            message: "❌ ${env.JOB_NAME} #${env.BUILD_NUMBER}: OWASP Dependency Check failed\nError: ${e.message}",
                            failOnError: false
                        )
                        error "OWASP Dependency Check failed"
                    }
                }
            }
        }
        
        stage('Build Docker Image') {
            steps {
                script {
                    try {
                        sh """
                        echo "Building Docker image..."
                        docker build -t ${ECR_REPO}:${env.BUILD_NUMBER} .
                        """
                        slackSend(channel: SLACK_CHANNEL, color: 'good', message: "✅ ${env.JOB_NAME} #${env.BUILD_NUMBER}: Docker image built successfully")
                    } catch (e) {
                        slackSend(channel: SLACK_CHANNEL, color: 'danger', message: "❌ ${env.JOB_NAME} #${env.BUILD_NUMBER}: Docker build failed")
                        error "Docker build failed"
                    }
                }
            }
        }
        
        stage('Image Vulnerability Scan') {
            steps {
                script {
                    try {
                        sh """
                        echo "Scanning Docker image for vulnerabilities..."
                        trivy image --exit-code 1 --severity CRITICAL --ignore-unfixed ${ECR_REPO}:${env.BUILD_NUMBER}
                        """
                        slackSend(channel: SLACK_CHANNEL, color: 'good', message: "✅ ${env.JOB_NAME} #${env.BUILD_NUMBER}: Docker image scan passed")
                    } catch (e) {
                        slackSend(channel: SLACK_CHANNEL, color: 'danger', message: "❌ ${env.JOB_NAME} #${env.BUILD_NUMBER}: Docker image scan found critical vulnerabilities")
                        error "Docker image scan failed"
                    }
                }
            }
        }
        
        stage('Push to ECR') {
            steps {
                script {
                    try {
                        withAWS(credentials: 'aws-credentials', region: AWS_REGION) {
                            sh """
                            echo "Logging in to ECR..."
                            aws ecr get-login-password | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com
                            
                            echo "Pushing image to ECR..."
                            docker push ${ECR_REPO}:${env.BUILD_NUMBER}
                            """
                        }
                        slackSend(channel: SLACK_CHANNEL, color: 'good', message: "✅ ${env.JOB_NAME} #${env.BUILD_NUMBER}: Docker image pushed to ECR")
                    } catch (e) {
                        slackSend(channel: SLACK_CHANNEL, color: 'danger', message: "❌ ${env.JOB_NAME} #${env.BUILD_NUMBER}: Failed to push Docker image to ECR")
                        error "Failed to push Docker image to ECR"
                    }
                }
            }
        }
        
        stage('Update ArgoCD Manifest') {
            steps {
                script {
                    try {
                        withCredentials([string(credentialsId: 'argocd-token', variable: 'ARGOCD_TOKEN')]) {
                            sh """
                            echo "Updating ArgoCD manifest with new image tag..."
                            
                            # Clone the GitOps repo
                            git clone https://github.com/hdas2/php-frontend.git
                            cd php-frontend
                            
                            # Update image tag in values.yaml
                            yq eval ".image.tag = \"${env.BUILD_NUMBER}\"" -i helm/charts/${APP_NAME}/values.yaml
                            
                            # Commit and push changes
                            git config user.name "hdas2"
                            git config user.email "hdas2@sastasundar.com"
                            git add charts/${APP_NAME}/values.yaml
                            git commit -m "Update ${APP_NAME} image to ${env.BUILD_NUMBER}"
                            git push origin main
                            
                            # Sync ArgoCD application
                            curl -X POST \
                                -H "Authorization: Bearer ${ARGOCD_TOKEN}" \
                                ${ARGOCD_SERVER}/api/v1/applications/${APP_NAME}/sync \
                                -d '{}'
                            """
                        }
                        slackSend(channel: SLACK_CHANNEL, color: 'good', message: "✅ ${env.JOB_NAME} #${env.BUILD_NUMBER}: ArgoCD manifest updated and synced")
                    } catch (e) {
                        slackSend(channel: SLACK_CHANNEL, color: 'danger', message: "❌ ${env.JOB_NAME} #${env.BUILD_NUMBER}: Failed to update ArgoCD manifest")
                        error "Failed to update ArgoCD manifest"
                    }
                }
            }
        }
    }
    
    post {
        always {
            // Clean up workspace
            cleanWs()
            
            // Send final build status
            script {
                def color = currentBuild.result == 'SUCCESS' ? 'good' : 'danger'
                def message = currentBuild.result == 'SUCCESS' ? 
                    "🎉 Pipeline SUCCESS: ${env.JOB_NAME} #${env.BUILD_NUMBER}" : 
                    "🔥 Pipeline FAILED: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
                
                slackSend(channel: SLACK_CHANNEL, color: color, message: message)
            }
        }
        
        success {
            // Archive artifacts on success
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }
        
        failure {
            script {
                echo "❌ Build failed at stage: ${env.STAGE_NAME}"
                
                // Send Slack alert
                slackSend(
                    channel: SLACK_CHANNEL,
                    color: 'danger',
                    message: "🔥 *${env.JOB_NAME}* #${env.BUILD_NUMBER} failed at stage *${env.STAGE_NAME}*. Check: ${env.BUILD_URL}"
                )
                
                // Mark build description
                currentBuild.description = "Build failed at stage: ${env.STAGE_NAME}"
                
                // Archive the console log or important artifacts
                archiveArtifacts artifacts: '**/logs/*.log', allowEmptyArchive: true
                
                // Optionally print environment info
                sh 'env | sort'
            }
        }
    }
}