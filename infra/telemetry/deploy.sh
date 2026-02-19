#!/bin/bash
# Deploy scanner telemetry infrastructure
# Prerequisites: gcloud CLI authenticated, project set

set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:-prooflayer-prod}"
REGION="${GCP_REGION:-us-central1}"
DATASET="scanner_telemetry"

echo "==> Creating BigQuery dataset (if not exists)..."
bq --project_id="$PROJECT_ID" mk --dataset --description "Scanner telemetry events" "$DATASET" 2>/dev/null || true

echo "==> Creating BigQuery table..."
bq query --project_id="$PROJECT_ID" --use_legacy_sql=false < schema.sql

echo "==> Creating aggregate views..."
bq query --project_id="$PROJECT_ID" --use_legacy_sql=false < views.sql

echo "==> Deploying Cloud Function..."
cd cloud-function
gcloud functions deploy scanner-telemetry-ingest \
  --project="$PROJECT_ID" \
  --region="$REGION" \
  --runtime=nodejs20 \
  --trigger-http \
  --allow-unauthenticated \
  --entry-point=ingestEvents \
  --memory=256MB \
  --timeout=30s \
  --max-instances=10 \
  --set-env-vars="GCP_PROJECT=$PROJECT_ID"
cd ..

echo "==> Done. Endpoint: https://$REGION-$PROJECT_ID.cloudfunctions.net/scanner-telemetry-ingest"
