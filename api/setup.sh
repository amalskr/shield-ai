#!/usr/bin/env bash
# Shield-AI: one time GCP setup + Cloud Run deploy. Run from this folder.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-shield-ai-2026}"   # change to your project id
REGION="${REGION:-asia-southeast1}"           # Singapore, closest to Sri Lanka
SERVICE="shield-ai-api"
SA_NAME="shield-ai-api"
SA="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud config set project "$PROJECT_ID"

echo ">> Enabling APIs"
gcloud services enable \
  run.googleapis.com \
  aiplatform.googleapis.com \
  webrisk.googleapis.com \
  firestore.googleapis.com \
  firebase.googleapis.com \
  firebasehosting.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com

echo ">> Service account (least privilege)"
gcloud iam service-accounts describe "$SA" >/dev/null 2>&1 || \
  gcloud iam service-accounts create "$SA_NAME" --display-name="Shield-AI API"

for ROLE in roles/aiplatform.user roles/datastore.user roles/logging.logWriter; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SA}" --role="$ROLE" --condition=None >/dev/null
done

echo ">> Firestore (native mode) + 3 day TTL on the scam cache"
gcloud firestore databases describe --database="(default)" >/dev/null 2>&1 || \
  gcloud firestore databases create --location="$REGION" --type=firestore-native
gcloud firestore fields ttls update expires_at --collection-group=scam_cache --enable-ttl --async || true

echo ">> Deploying to Cloud Run"
gcloud run deploy "$SERVICE" \
  --source . \
  --region "$REGION" \
  --service-account "$SA" \
  --allow-unauthenticated \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 3 \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=${PROJECT_ID},MODEL_ID=gemini-2.5-flash-lite,GEMINI_LOCATION=global"

URL=$(gcloud run services describe "$SERVICE" --region "$REGION" --format='value(status.url)')
echo ">> Deployed: $URL"
echo "   Test: API_URL=$URL ./test.sh"
