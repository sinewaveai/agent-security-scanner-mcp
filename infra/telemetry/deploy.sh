#!/bin/bash
# Deploy scanner telemetry infrastructure to GCP
# Usage: GCP_PROJECT_ID=<project> ./deploy.sh
#
# Prerequisites:
#   - gcloud CLI authenticated (`gcloud auth login`)
#   - Billing enabled on the target project

set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:?Set GCP_PROJECT_ID before running this script}"
REGION="${GCP_REGION:-us-central1}"
DATASET="scanner_telemetry"
SA_NAME="scanner-telemetry-ingest"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Deploying to project: $PROJECT_ID (region: $REGION)"

# --- Step 1: Enable required APIs ---
echo "==> Enabling required APIs..."
gcloud services enable \
  cloudfunctions.googleapis.com \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  bigquery.googleapis.com \
  --project="$PROJECT_ID"

# --- Step 2: Create service account (if not exists) ---
echo "==> Creating service account (if not exists)..."
if ! gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" &>/dev/null; then
  gcloud iam service-accounts create "$SA_NAME" \
    --display-name="Scanner Telemetry Ingest" \
    --project="$PROJECT_ID"

  # Grant BigQuery data insert
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/bigquery.dataEditor" \
    --quiet

  # Grant BigQuery job creation (needed for streaming inserts)
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/bigquery.jobUser" \
    --quiet

  echo "    Created $SA_EMAIL with BigQuery roles"
else
  echo "    Service account $SA_EMAIL already exists"
fi

# --- Step 3: Create BigQuery dataset + table + views ---
echo "==> Creating BigQuery dataset (if not exists)..."
bq --project_id="$PROJECT_ID" mk --dataset --description "Scanner telemetry events" "$DATASET" 2>/dev/null || true

echo "==> Creating BigQuery table..."
bq query --project_id="$PROJECT_ID" --use_legacy_sql=false < "$SCRIPT_DIR/schema.sql"

echo "==> Creating aggregate views..."
bq query --project_id="$PROJECT_ID" --use_legacy_sql=false < "$SCRIPT_DIR/views.sql"

# --- Step 4: Deploy Cloud Function (gen2) ---
echo "==> Deploying Cloud Function (gen2)..."
gcloud functions deploy scanner-telemetry-ingest \
  --project="$PROJECT_ID" \
  --region="$REGION" \
  --trigger-http \
  --allow-unauthenticated \
  --runtime=nodejs20 \
  --entry-point=ingestEvents \
  --memory=256MB \
  --timeout=30s \
  --max-instances=10 \
  --gen2 \
  --service-account="$SA_EMAIL" \
  --set-env-vars="GCP_PROJECT=$PROJECT_ID" \
  --source="$SCRIPT_DIR/cloud-function"

# --- Print deployed URL ---
ENDPOINT=$(gcloud functions describe scanner-telemetry-ingest \
  --project="$PROJECT_ID" --region="$REGION" --gen2 \
  --format='value(serviceConfig.uri)')

echo ""
echo "==> Deployment complete!"
echo "    Endpoint: $ENDPOINT"
echo ""
echo "    Test with:"
echo "    curl -X POST '$ENDPOINT' \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"events\":[{\"schema_version\":1,\"event\":\"test.probe\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"machine_id\":\"deploy-test\"}]}'"
