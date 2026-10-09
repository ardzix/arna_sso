// SSO release source of truth. Uses the already approved manager and SSH identity.
// Secrets remain in immutable Swarm secrets, never copied into Docker builds.
pipeline {
    agent any
    options { timestamps(); timeout(time: 60, unit: 'MINUTES'); disableConcurrentBuilds(); buildDiscarder(logRotator(numToKeepStr: '20')) }
    parameters { booleanParam(name: 'DEPLOY', defaultValue: false, description: 'Roll the tested main artifact after the migration gate') }
    stages {
        stage('Checkout approved source') {
            steps {
                deleteDir()
                git branch: 'main', url: 'https://github.com/ardzix/arna_sso.git'
                sh 'git diff --exit-code; git rev-parse HEAD > release-commit.txt; command -v ssh; command -v scp'
            }
        }
        stage('Test and publish exact artifact') {
            steps {
                withCredentials([sshUserPrivateKey(credentialsId: 'stag-arnatech-sa-01', keyFileVariable: 'SSO_SSH_KEY')]) {
                    sh '''
                        set -eu
                        set +x
                        ssh -i "$SSO_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15 root@arnatech.id 'mkdir -p /root/arnatech-releases; chmod 700 /root/arnatech-releases'
                        scp -i "$SSO_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=yes deploy/release.py root@arnatech.id:/root/arnatech-releases/sso-release-entry.py
                        ssh -i "$SSO_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15 root@arnatech.id python3 /root/arnatech-releases/sso-release-entry.py build "$(cat release-commit.txt)"
                    '''
                }
            }
        }
        stage('Migrate, roll and verify') {
            when { expression { params.DEPLOY } }
            steps {
                withCredentials([sshUserPrivateKey(credentialsId: 'stag-arnatech-sa-01', keyFileVariable: 'SSO_SSH_KEY')]) {
                    sh '''
                        set -eu
                        set +x
                        ssh -i "$SSO_SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15 root@arnatech.id python3 /root/arnatech-releases/sso-release-entry.py roll "$(cat release-commit.txt)"
                    '''
                }
            }
        }
    }
}
