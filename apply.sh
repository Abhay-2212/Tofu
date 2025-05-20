#!/bin/bash

# Function to prompt the user for the password securely
prompt_for_password() {
  read -s -p "Enter RDS password (at least 8 characters): " RDS_PASSWORD
  echo

  # Check if password is at least 8 characters
  if [ ${#RDS_PASSWORD} -lt 8 ]; then
    echo "Error: Password must be at least 8 characters long."
    exit 1
  fi
}

# Prompt for the password and verify its length
prompt_for_password

# Ask for password confirmation
read -s -p "Re-enter RDS password to confirm: " RDS_PASSWORD_CONFIRM
echo

# Check if passwords match
if [ "$RDS_PASSWORD" != "$RDS_PASSWORD_CONFIRM" ]; then
  echo "Error: Passwords do not match. Exiting."
  exit 1
fi

# Run tofu apply with the password passed as a variable
tofu apply -var="rds_password=$RDS_PASSWORD" -auto-approve
