pipeline {
    agent any 
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

        TRIVY_PATH = '/usr/bin/trivy'
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
                    sh '''
                    cd /applications/php-frontend
                    composer lint
                    echo "Running PHP lint check..."
                    '''
                }   
            }
        }

        stage('Composer Unit Tests') {
            steps {
                script {
                    try {
                        sh '''
                        cd /applications/php-frontend
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
                        cd /applications/php-frontend
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
                            cd /applications/php-frontend \
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
        
        stage('Scan with Trivy') {
            steps {
                script {
                    // Run Trivy scan in the workspace directory
                    sh """
                        ${TRIVY_PATH} fs --security-checks vuln \
                        --format json --output trivy-report.json .
                    """
                    
                    // Check if report was generated
                    if (fileExists('trivy-report.json')) {
                        def report = readJSON file: 'trivy-report.json'
                        sendTrivyReportToSlack(report)
                    } else {
                        slackSend(
                            channel: '#security-alerts',
                            message: ':warning: Failed to generate Trivy scan report',
                            color: 'warning'
                        )
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
                        cd /applications/php-frontend
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
                        cd /applications/php-frontend
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
                        cd /applications/php-frontend
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
                            cd /applications/php-frontend
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
                            cd /applications/php-frontend
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

def sendTrivyReportToSlack(report) {
    // Count vulnerabilities by severity
    def critical = 0
    def high = 0
    def medium = 0
    def low = 0
    
    report.Results.each { result ->
        result.Vulnerabilities?.each { vuln ->
            switch(vuln.Severity) {
                case 'CRITICAL': critical++; break
                case 'HIGH': high++; break
                case 'MEDIUM': medium++; break
                case 'LOW': low++; break
            }
        }
    }
    
    // Prepare Slack message
    def message = """
*Trivy Scan Results* :shield:
        
:red_circle: *Critical*: ${critical}
:large_orange_circle: *High*: ${high}
:yellow_circle: *Medium*: ${medium}
:white_circle: *Low*: ${low}
        
*Top Findings:*
${getTopFindings(report, 3)}
"""
    
    // Send to Slack
    slackSend(
        channel: '#security-alerts',
        message: message,
        color: critical > 0 ? 'danger' : (high > 0 ? 'warning' : 'good')
    )
}

def getTopFindings(report, limit) {
    def findings = []
    report.Results.each { result ->
        result.Vulnerabilities?.each { vuln ->
            findings << [
                severity: vuln.Severity,
                title: vuln.Title ?: vuln.VulnerabilityID,
                package: "${vuln.PkgName}@${vuln.InstalledVersion}",
                fixed: vuln.FixedVersion ?: 'No fix available'
            ]
        }
    }
    
    // Sort by severity (critical first)
    findings = findings.sort { -getSeverityWeight(it.severity) }
    
    // Format top findings
    def formatted = []
    findings.take(limit).eachWithIndex { finding, index ->
        def emoji = getSeverityEmoji(finding.severity)
        formatted << "${index+1}. ${emoji} *${finding.severity}*: ${finding.title}"
        formatted << "   - Package: ${finding.package}"
        formatted << "   - Fixed in: ${finding.fixed}"
    }
    
    return formatted.join('\n')
}

def getSeverityWeight(severity) {
    switch(severity) {
        case 'CRITICAL': return 4
        case 'HIGH': return 3
        case 'MEDIUM': return 2
        case 'LOW': return 1
        default: return 0
    }
}

def getSeverityEmoji(severity) {
    switch(severity) {
        case 'CRITICAL': return ':red_circle:'
        case 'HIGH': return ':large_orange_circle:'
        case 'MEDIUM': return ':yellow_circle:'
        case 'LOW': return ':white_circle:'
        default: return ':grey_question:'
    }
}