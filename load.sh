#!/bin/bash
for f in examples/*.txt; do
  echo "Uploading $f"
  curl -s -X POST "http://localhost:8000/api/v1/upload-config" -F "file=@$f" | jq -c
done