#!/bin/bash
set -e

ARTIFACTORY_REPOSITORY_URL="$1"
TRIGGER_DEPLOY="$2"
RUN_SONAR="$3"
BASE_PATH="$ARTIFACTORY_REPOSITORY_URL/com/mendix"
PROJECT_ID="devops/ssltools"

if [ -z "$ARTIFACTORY_REPOSITORY_URL" ]; then
    echo "No artifactory repository URL given: " $0 "https://example.com/blah-local"
    exit 1
fi

export LL_COMMIT=$(git rev-parse HEAD | cut -c1-8)
export VERSION="${CI_BUILD_REF_NAME}_${CI_BUILD_ID}_${CI_BUILD_REF:0:8}"
JAVA_HOME=/usr/lib/jvm/jdk-7u80-oracle-x64/jre mvn package -Dbuild.version="${VERSION}"

cp $(pwd)/pom.xml ssltools-${VERSION}.pom

push-to-artifactory.sh $(pwd)/target/ssltools-*_*.jar $BASE_PATH/ssltools/$VERSION
push-to-artifactory.sh $(pwd)/ssltools-${VERSION}.pom $BASE_PATH/ssltools/$VERSION

if [ "$RUN_SONAR" == "run-sonar" ]; then
    run-sonar-analysis.sh ${CI_BUILD_REF} ${CI_BUILD_REF_NAME} ${PROJECT_ID}
fi
