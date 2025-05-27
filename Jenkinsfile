pipeline {
    agent any 
    options {
    disableConcurrentBuilds()
    }
    environment {
        // Application Configuration
        APP_NAME = 'php-frontend'
        DOCKER_IMAGE = 'php-frontend'
        
        // AWS Configuration
        AWS_ACCOUNT_ID = '699951450237'
        AWS_REGION = 'ap-south-1'
        ECR_REPO = "699951450237.dkr.ecr.ap-south-1.amazonaws.com/rspl-sandbox-ecr"
        
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
                        // Run Dependency Check (generate CSV and HTML)
                        sh '''
                        mkdir -p reports
                        cd /applications/php-frontend
                        dependency-check \
                            --project ${APP_NAME} \
                            --out ${APP_DIR}/reports \
                            --scan . \
                            --format CSV \
                            --format HTML \
                            --nvdApiKey ${NVD_API_KEY} \
                            --log ${APP_DIR}/reports/dependency-check.log
                        '''

                        def csvFile = "${APP_DIR}/reports/dependency-check-report.csv"

                        if (!fileExists(csvFile)) {
                            error "Dependency Check CSV report not found at: ${csvFile}"
                        }

                        def csvContent = readFile(csvFile)
                        if (!csvContent?.trim()) {
                            error "Dependency Check CSV report is empty"
                        }

                        def lines = csvContent.split('\n') as List
                        if (lines.size() < 2) {
                            error "No vulnerabilities found in Dependency Check report"
                        }

                        // --- CSV Line Parser Function ---
                        @NonCPS
                        def parseCSVLine = { line ->
                            def matcher = line =~ /(?:^|,)(?:"([^"]*)"|([^",]*))/
                            def result = []
                            while (matcher.find()) {
                                result << (matcher.group(1) ?: matcher.group(2))
                            }
                            return result
                        }

                        def headers = parseCSVLine(lines[0]).collect { it.trim() }
                        def severityCount = [CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0]
                        def findings = []

                        for (int i = 1; i < lines.size(); i++) {
                            def values = parseCSVLine(lines[i])
                            def row = [:]
                            headers.eachWithIndex { header, index ->
                                row[header] = index < values.size() ? values[index] : null
                            }

                            def sev = row['CVSSv3_BaseSeverity']?.toUpperCase() ?:
                                    row['CVSSv2_Severity']?.toUpperCase() ?:
                                    (row['CVSSv3_BaseScore']?.isFloat() && row['CVSSv3_BaseScore'].toFloat() >= 9.0 ? 'CRITICAL' :
                                    row['CVSSv3_BaseScore']?.isFloat() && row['CVSSv3_BaseScore'].toFloat() >= 7.0 ? 'HIGH' :
                                    row['CVSSv3_BaseScore']?.isFloat() && row['CVSSv3_BaseScore'].toFloat() >= 4.0 ? 'MEDIUM' :
                                    row['CVSSv3_BaseScore']?.isFloat() && row['CVSSv3_BaseScore'].toFloat() > 0 ? 'LOW' :
                                    row['CVSSv2_Score']?.isFloat() && row['CVSSv2_Score'].toFloat() >= 7.0 ? 'HIGH' :
                                    row['CVSSv2_Score']?.isFloat() && row['CVSSv2_Score'].toFloat() >= 4.0 ? 'MEDIUM' :
                                    row['CVSSv2_Score']?.isFloat() && row['CVSSv2_Score'].toFloat() > 0 ? 'LOW' : null)

                            if (sev) {
                                sev = sev.contains('CRIT') ? 'CRITICAL' :
                                    sev.contains('HIGH') ? 'HIGH' :
                                    sev.contains('MED') ? 'MEDIUM' :
                                    sev.contains('LOW') ? 'LOW' : sev

                                if (sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
                                    severityCount[sev] = (severityCount[sev] ?: 0) + 1
                                    findings << [
                                        severity: sev,
                                        package: "${row['DependencyName'] ?: 'N/A'}:${row['Version'] ?: 'N/A'}",
                                        cve: row['CVE'] ?: 'N/A',
                                        score: row['CVSSv3_BaseScore'] ?: row['CVSSv2_Score'] ?: 'N/A',
                                        description: row['ShortDescription']?.take(100) ?: 
                                                    row['Vulnerability']?.take(100) ?: 'No description'
                                    ]
                                }
                            }
                        }

                        def top10 = findings.sort { a, b ->
                            def scoreA = a.score == 'N/A' ? 0 : a.score.toFloat()
                            def scoreB = b.score == 'N/A' ? 0 : b.score.toFloat()
                            return scoreB <=> scoreA
                        }.take(10)

                        def tableHeader = "| Severity | Package           | CVE ID       | Score | Description              |\n" +
                                        "|----------|-------------------|--------------|-------|--------------------------|"
                        def tableRows = top10.collect {
                            "| ${it.severity.padRight(8)} | ${(it.package ?: 'N/A').take(17).padRight(17)} | ${(it.cve ?: 'N/A').take(12).padRight(12)} | ${(it.score ?: 'N/A').toString().padRight(5)} | ${(it.description ?: 'N/A').take(24).padRight(24)} |"
                        }.join("\n")

                        def slackMessage = """
                        *Dependency Check Summary for ${APP_NAME}*

                        :rotating_light: *Critical*: ${severityCount.CRITICAL ?: 0}
                        :large_orange_circle: *High*: ${severityCount.HIGH ?: 0}
                        :yellow_circle: *Medium*: ${severityCount.MEDIUM ?: 0}
                        :white_circle: *Low*: ${severityCount.LOW ?: 0}

                        *Top 10 Vulnerabilities:*
                        ```
                        ${tableHeader}
                        ${tableRows}
                        ```
                        """

                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: severityCount.CRITICAL > 0 ? 'danger' :
                                severityCount.HIGH > 0 ? 'warning' : 'good',
                            message: slackMessage,
                            filePath: "${APP_DIR}/reports/dependency-check-report.html"
                        )

                        if ((severityCount.CRITICAL ?: 0) > 0) {
                            error "Build failed: ${severityCount.CRITICAL} critical vulnerabilities found"
                        }

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
                        // Run Trivy scan in the application directory
                        sh """
                            cd ${APP_DIR}
                            echo "Running Trivy image scan..."
                            trivy image --format json --output trivy-image-report.json --ignore-unfixed ${ECR_REPO}:${env.BUILD_NUMBER}
                            trivy image --format table --output trivy-image-report.txt --ignore-unfixed ${ECR_REPO}:${env.BUILD_NUMBER}
                        """

                        // Copy reports to workspace
                        sh "cp ${APP_DIR}/trivy-image-report.json ./"
                        sh "cp ${APP_DIR}/trivy-image-report.txt ./"

                        // Extract and format vulnerability summary using jq
                        def vulnCountsJson = sh(
                            script: "jq '[.Results[].Vulnerabilities[]?.Severity] | group_by(.) | map({(.[0]): length}) | add' trivy-image-report.json",
                            returnStdout: true
                        ).trim()
                        def summary = readJSON text: vulnCountsJson

                        // Emoji map for severity levels
                        def emojiMap = [
                            "CRITICAL": "🚨",
                            "HIGH":     "🔴",
                            "MEDIUM":   "🟠",
                            "LOW":      "🟡",
                            "UNKNOWN":  "⚪"
                        ]

                        // Format Slack summary
                        def summaryText = summary.collect { severity, count ->
                            String sev = severity.padRight(8)
                            "${emojiMap.get(severity, '')} *${sev}*: ${count}"
                        }.join("\n")

                        // Send visual Slack summary
                        slackSend(
                            channel: SLACK_CHANNEL,
                            color: summary['CRITICAL']?.toInteger() > 0 ? 'danger' : 'good',
                            message: """\
                        🛡️ *Trivy Scan Summary* for `${env.JOB_NAME}` #${env.BUILD_NUMBER}

                        ${summaryText}
                        """
                        )

                        // Upload full table report to Slack
                        slackUploadFile(
                            channel: SLACK_CHANNEL,
                            filePath: 'trivy-image-report.txt',
                            initialComment: "📄 *Full Trivy Report* for `${env.JOB_NAME}` #${env.BUILD_NUMBER}"
                        )

                        // Fail build on CRITICAL vulnerabilities
                        if (summary['CRITICAL']?.toInteger() > 0) {
                            error "Trivy found CRITICAL vulnerabilities"
                        }

                    } catch (e) {
                        slackSend(
                            channel: SLACK_CHANNEL,
                            color: 'danger',
                            message: "❌ `${env.JOB_NAME}` #${env.BUILD_NUMBER}: Trivy scan failed: ${e.getMessage()}"
                        )
                        error "Docker image scan stage failed"
                    }
                }
            }
        }

        stage('Push to ECR') {
            steps {
                script {
                    try {
                        // Bind AWS credentials stored in Jenkins credential 'aws-credentials'
                        withCredentials([[
                            $class: 'AmazonWebServicesCredentialsBinding',
                            credentialsId: 'aws-credentials',
                            accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                            secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                        ]]) {
                            sh """
                            cd /applications/php-frontend
                            echo "Logging in to ECR..."
                            aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

                            echo "Pushing Docker image ${ECR_REPO}:${env.BUILD_NUMBER} to ECR..."
                            docker push ${ECR_REPO}:${env.BUILD_NUMBER}
                            """
                        }

                        slackSend(
                            channel: SLACK_CHANNEL,
                            color: 'good',
                            message: "✅ ${env.JOB_NAME} #${env.BUILD_NUMBER}: Docker image pushed to ECR"
                        )
                    } catch (e) {
                        echo "Push to ECR failed: ${e}"
                        slackSend(
                            channel: SLACK_CHANNEL,
                            color: 'danger',
                            message: "❌ ${env.JOB_NAME} #${env.BUILD_NUMBER}: Failed to push Docker image to ECR"
                        )
                        error("Failed to push Docker image to ECR")
                    }
                }
            }
        }

        stage('Update ArgoCD Manifest') {
            steps {
                script {
                    try {
                        withCredentials([string(credentialsId: 'argocd-token', variable: 'ARGOCD_TOKEN')]) {
                            dir('/applications/php-frontend') {
                                // Update ArgoCD manifest with new image tag
                                echo "Updating ArgoCD manifest with new image tag..."
                                sh """
                                    # Update image tag in values.yaml
                                    yq e '.image.tag = "${BUILD_NUMBER}"' -i helm/charts/values.yaml

                                    # Commit and push changes
                                    cd ${APP_DIR}
                                    git config user.name "hdas2"
                                    git config user.email "hdas2@sastasundar.com"
                                    git add helm/charts/values.yaml
                                    git commit -m "Update ${APP_NAME} image to ${BUILD_NUMBER}" || echo 'No changes to commit'
                                    git push origin main
                                """

                                // Use safe curl call outside of the shell
                                withEnv(["ARGOCD_TOKEN=${ARGOCD_TOKEN}"]) {
                                    sh '''
                                        curl -X POST \
                                        -H "Authorization: Bearer $ARGOCD_TOKEN" \
                                        ${ARGOCD_SERVER}/api/v1/applications/${APP_NAME}/sync \
                                        -d '{}'
                                    '''
                                }
                            }
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
def processScanResults(appDir) {
    def reportPath = "${appDir}/reports"
    def jsonPath = "${reportPath}/dependency-check-report.json"
    def csvPath = "${reportPath}/dependency-check-report.csv"
    def htmlPath = "${reportPath}/dependency-check-report.html"

    if (!fileExists(jsonPath)) {
        error "Dependency Check JSON report not found at ${jsonPath}"
    }

    echo "📖 Reading Dependency Check report at ${jsonPath}"
    def report = readJSON file: jsonPath
    def vulnCounts = [CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0]

    report.dependencies.each { dep ->
        dep.vulnerabilities?.each { vuln ->
            def severity = vuln.severity?.toUpperCase()
            if (vulnCounts.containsKey(severity)) {
                vulnCounts[severity]++
            }
        }
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
