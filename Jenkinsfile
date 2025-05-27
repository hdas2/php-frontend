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
                        echo "🔍 Running OWASP Dependency Check..."

                        def outputDir = "${APP_DIR}/reports"
                        def jsonReport = "${outputDir}/dependency-check-report.json"
                        def htmlReport = "${outputDir}/dependency-check-report.html"
                        def logFile = "${outputDir}/dependency-check.log"

                        // Run the actual scan (example command — adjust based on your tool/integration)
                        sh """
                        cd ${APP_DIR} \
                            dependency-check \
                                --project ${env.JOB_NAME} \
                                --nvdApiKey ${NVD_API_KEY} \
                                --scan . \
                                --scan ${APP_DIR} \
                                --out ${outputDir} \
                                --format ALL \
                                --log ${logFile}
                        """

                        // Display report files for debugging
                        echo "📂 Verifying reports at: ${outputDir}"
                        sh "ls -l ${outputDir}"

                        // Show log content if reports are missing
                        if (!fileExists(jsonReport) || !fileExists(htmlReport)) {
                            def logContent = fileExists(logFile) ? readFile(logFile).take(1000) : 'No log file available'
                            echo "🛑 Dependency Check log:\n${logContent}"
                            error "Dependency Check failed to generate required reports."
                        }

                        // Process and send to Slack
                        processScanResults(APP_DIR)

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


// OWASP Dependency Check Report Processor
def processScanResults() {
    // Parse JSON report
    def report = readJSON file: "${WORKSPACE}/reports/dependency-check-report.json"
    
    // Count vulnerabilities
    def vulnCounts = [CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0]
    def findings = []
    
    report.dependencies.each { dep ->
        dep.vulnerabilities?.each { vuln ->
            def severity = vuln.severity?.toUpperCase()
            if (vulnCounts.containsKey(severity)) {
                vulnCounts[severity]++
                findings << [
                    severity: severity,
                    package: dep.fileName,
                    cve: vuln.name,
                    cvss: vuln.cvssv3?.baseScore ?: vuln.cvssv2?.score ?: 'N/A',
                    description: vuln.description?.take(100) ?: 'No description'
                ]
            }
        }
    }
    
    // Generate Markdown table
    def tableHeader = "| Severity | Package | CVE | CVSS | Description |\n|----------|---------|-----|------|-------------|"
    def tableRows = findings.take(10).collect { finding ->
        "| ${finding.severity} | ${finding.package} | ${finding.cve} | ${finding.cvss} | ${finding.description} |"
    }.join("\n")
    
    def fullTable = "${tableHeader}\n${tableRows}"
    
    // Send to Slack
    slackSend(
        channel: env.SLACK_CHANNEL,
        color: vulnCounts.CRITICAL > 0 ? 'danger' : (vulnCounts.HIGH > 0 ? 'warning' : 'good'),
        message: """
        *Dependency Check Results Summary*
        Critical: ${vulnCounts.CRITICAL} :red_circle:
        High: ${vulnCounts.HIGH} :large_orange_circle:
        Medium: ${vulnCounts.MEDIUM} :yellow_circle:
        Low: ${vulnCounts.LOW} :white_circle:
        
        *Top Vulnerabilities*
        ```
        ${fullTable}
        ```
        """
    )
    
    // Fail build if critical vulnerabilities found
    if (vulnCounts.CRITICAL > 0) {
        error "Build failed: ${vulnCounts.CRITICAL} critical vulnerabilities found"
    }

    def generateSlackCsvTable(findings) {
    def csvHeader = "Severity,Package,CVE,CVSS,Description"
    def csvRows = findings.take(10).collect { finding ->
        "${finding.severity},${finding.package},${finding.cve},${finding.cvss},\"${finding.description}\""
    }.join("\n")
    
    return "${csvHeader}\n${csvRows}"
}

// Then in your slackSend:
message: """
*Dependency Check Results*
Critical: ${vulnCounts.CRITICAL}
High: ${vulnCounts.HIGH}
Medium: ${vulnCounts.MEDIUM}
Low: ${vulnCounts.LOW}

*Top Vulnerabilities*
\`\`\`
${generateSlackCsvTable(findings)}
\`\`\`
"""
def formatForSlack(findings) {
    def maxWidths = [severity: 8, package: 30, cve: 15, cvss: 5, description: 50]
    
    // Format header
    def header = "```\n" +
        "Severity".padRight(maxWidths.severity) + " | " +
        "Package".padRight(maxWidths.package) + " | " +
        "CVE".padRight(maxWidths.cve) + " | " +
        "CVSS".padRight(maxWidths.cvss) + " | " +
        "Description".padRight(maxWidths.description) + "\n" +
        "-".padRight(maxWidths.severty, '-') + "-|-" +
        "-".padRight(maxWidths.package, '-') + "-|-" +
        "-".padRight(maxWidths.cve, '-') + "-|-" +
        "-".padRight(maxWidths.cvss, '-') + "-|-" +
        "-".padRight(maxWidths.description, '-') + "\n"
    
    // Format rows
    def rows = findings.take(10).collect { finding ->
        finding.severity.padRight(maxWidths.severity) + " | " +
        finding.package.take(maxWidths.package).padRight(maxWidths.package) + " | " +
        finding.cve.take(maxWidths.cve).padRight(maxWidths.cve) + " | " +
        finding.cvss.toString().padRight(maxWidths.cvss) + " | " +
        finding.description.take(maxWidths.description).padRight(maxWidths.description)
    }.join("\n")
    
    return header + rows + "\n```"
}

    // Slack summary
    def color = vulnCounts.CRITICAL > 0 ? 'danger' :
                vulnCounts.HIGH > 0 ? 'warning' : 'good'

    slackSend(
        channel: env.SLACK_CHANNEL,
        color: color,
        message: """
        :shield: *Dependency Check Results* - `${env.JOB_NAME}`
        *Critical:* ${vulnCounts.CRITICAL} :red_circle:
        *High:* ${vulnCounts.HIGH} :orange_circle:
        *Medium:* ${vulnCounts.MEDIUM} :yellow_circle:
        *Low:* ${vulnCounts.LOW} :white_circle:
        """
    )

    // Optional CSV snippet
    if (fileExists(csvPath)) {
        def csvContent = readFile(csvPath).take(3000)
        slackSend(
            channel: env.SLACK_CHANNEL,
            color: '#CCCCCC',
            message: ":page_facing_up: *CSV Report Snippet:* \n```" + csvContent + "```"
        )
    } else {
        echo "CSV report not found at ${csvPath}"
    }

    // Attach HTML report
    if (fileExists(htmlPath)) {
        slackUploadFile(
            filePath: htmlPath,
            filename: "dependency-check-report.html",
            title: "Dependency Check HTML Report",
            initialComment: ":mag: HTML Report for `${env.JOB_NAME}`",
            channel: env.SLACK_CHANNEL
        )
    } else {
        echo "HTML report not found at ${htmlPath}"
    }

    // Optionally fail build on critical vulns
    if (vulnCounts.CRITICAL > 0) {
        error "Build failed: ${vulnCounts.CRITICAL} critical vulnerabilities found"
    }
}
