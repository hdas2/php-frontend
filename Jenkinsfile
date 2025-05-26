pipeline {
    agent any 
    options {
    disableConcurrentBuilds()
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

        TRIVY_PATH = '/usr/bin/trivy'
        NVD_API_KEY = credentials('nvd_api_key')
        DB_URL = 'jdbc:postgresql://localhost:5432/dependencycheck'
        DB_USER = 'dcheck-user'
        DATA_DIR = "${WORKSPACE}/dc-data"
        APP_DIR = '/applications/php-frontend'
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
                    // Run Trivy scan
                    sh 'trivy fs --security-checks vuln --format json --output trivy-report.json .'
                    
                    // Parse JSON (alternative if readJSON not available)
                    def jsonText = readFile('trivy-report.json')
                    def report = new groovy.json.JsonSlurper().parseText(jsonText)
                    
                    // Prepare message
                    def message = buildSlackMessage(report)
                    
                    // Send to Slack with proper error handling
                    try {
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: message.color,
                            message: message.text,
                            tokenCredentialId: 'slack-jenkins-token',
                            failOnError: true
                        )
                    } catch (Exception e) {
                        echo "Slack notification failed: ${e.getMessage()}"
                        // Fallback notification or other error handling
                    }
                }
            }
        }

        stage('Dependency Check') {
            steps {
                script {
                try {
                    lock(resource: 'dependency-check-db') {
                    def exitCode = sh(
                        script: """
                        cd ${APP_DIR}
                        dependency-check \
                            --project php-frontend \
                            --out ${APP_DIR}/reports \
                            --scan . \
                            --format JSON \
                            --format HTML \
                            --nvdApiKey ${NVD_API_KEY} \
                            --enableExperimental \
                            --data /opt/dependency-check/data \
                            --log ${APP_DIR}/reports/dependency-check.log
                        """,
                        returnStatus: true
                    )

                    if (exitCode != 0) {
                        def logPath = "${APP_DIR}/reports/dependency-check.log"
                        def logContent = fileExists(logPath) ? readFile(logPath).take(1000) : 'No log file available'

                        error """
                        Dependency Check failed with exit code ${exitCode}
                        Log snippet:
                        ${logContent}
                        """
                    }

                    // Verify reports were generated
                    if (!fileExists('${APP_DIR}/reports/dependency-check-report.json') || 
                        !fileExists('${APP_DIR}/reports/dependency-check-report.html')) {
                        error "Dependency Check failed to generate reports"
                    }
                    }

                    // Process and send results
                    processScanResults()

                } catch (Exception e) {
                    slackSend(
                    channel: env.SLACK_CHANNEL,
                    color: 'danger',
                    message: ":alert: *Dependency Check Failed* - ${e.message}"
                    )
                    error "Dependency Check failed: ${e.message}"
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

// Function to build Slack message from Trivy report
def buildSlackMessage(report) {
    // Count vulnerabilities by severity
    def counts = [CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0]
    
    report.Results.each { result ->
        result.Vulnerabilities?.each { vuln ->
            counts[vuln.Severity] = (counts[vuln.Severity] ?: 0) + 1
        }
    }
    
    // Determine message color
    def color = counts.CRITICAL > 0 ? 'danger' : 
               counts.HIGH > 0 ? 'warning' : 'good'
    
    // Build message text
    def text = """
*Trivy Vulnerability Scan Results* :shield:
• :red_circle: *Critical*: ${counts.CRITICAL}
• :large_orange_circle: *High*: ${counts.HIGH}
• :yellow_circle: *Medium*: ${counts.MEDIUM}
• :white_circle: *Low*: ${counts.LOW}
"""
    
    return [color: color, text: text]
}



// Depedency Check processing function
def processScanResults() {
    // Parse JSON report
    def report = readJSON file: "${APP_DIR}/reports/dependency-check-report.json"
    
    // Count vulnerabilities
    def vulnCounts = [CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0]
    report.dependencies.each { dep ->
        dep.vulnerabilities?.each { vuln ->
            def severity = vuln.severity?.toUpperCase()
            if (vulnCounts.containsKey(severity)) {
                vulnCounts[severity]++
            }
        }
    }
    
    // Send Slack notification
    def color = vulnCounts.CRITICAL > 0 ? 'danger' : 
               vulnCounts.HIGH > 0 ? 'warning' : 'good'
    
    slackSend(
        channel: env.SLACK_CHANNEL,
        color: color,
        message: """
        :shield: *Dependency Check Results* - ${env.JOB_NAME}
        Critical: ${vulnCounts.CRITICAL} :red_circle:
        High: ${vulnCounts.HIGH} :orange_circle:
        Medium: ${vulnCounts.MEDIUM} :yellow_circle:
        Low: ${vulnCounts.LOW} :white_circle:
        """,
        filePath: "${APP_DIR}/reports/dependency-check-report.html"
    )
    
    // Fail build if critical vulnerabilities found
    if (vulnCounts.CRITICAL > 0) {
        error "Build failed: ${vulnCounts.CRITICAL} critical vulnerabilities found"
    }
}