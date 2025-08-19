#!/usr/bin/env bash

set -euo pipefail

# Source .env file if it exists
if [ -f "$(dirname "$0")/.env" ]; then
    source "$(dirname "$0")/.env"
fi

# Variables
HSM_USER="${HSM_USER:-}"
HSM_PASSWORD="${HSM_PASSWORD:-}"
LABEL="${LABEL:-}"
KEYSIZE_BITS="${KEYSIZE_BITS:-4096}"

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Create certificates for CloudHSM

OPTIONS:
    -u, --user USER         Username for CloudHSM
    -p, --password PASS     Password for CloudHSM
    -l, --label LABEL       Labe for the generated keypair in CloudHSM
    -h, --help              Show this help message

ENVIRONMENT:
    The script will source default values from a .env file if present in the same directory.
    Environment variables:
        HSM_USER
        HSM_PASSWORD
        LABEL

EXAMPLES:
    $0 -u myuser -p mypass -l mylabel
    $0 --user admin --password secret --label mylabel

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--user)
            HSM_USER="$2"
            shift 2
            ;;
        -p|--password)
            HSM_PASSWORD="$2"
            shift 2
            ;;
        -l|--label)
            LABEL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option $1" >&2
            usage
            exit 1
            ;;
    esac
done

# Validation
if [ -z "$HSM_USER" ]; then
    echo "Error: User is required. Use -u or set HSM_USER in .env file." >&2
    exit 1
fi

if [ -z "$HSM_PASSWORD" ]; then
    echo "Error: Password is required. Use -p or set HSM_PASSWORD in .env file." >&2
    exit 1
fi

if [ -z "$LABEL" ]; then
    echo "Error: LABEL is required. Use -l or set LABEL in .env file." >&2
    exit 1
fi

# Check for required executables
echo "Checking for required executables..."
MISSING_EXECUTABLES=()

if ! command -v cloudhsm-cli &> /dev/null; then
    MISSING_EXECUTABLES+=("cloudhsm-cli")
fi

if ! command -v openssl &> /dev/null; then
    MISSING_EXECUTABLES+=("openssl")
fi

if [ ${#MISSING_EXECUTABLES[@]} -ne 0 ]; then
    echo "Error: The following required executables are not found on PATH:" >&2
    for executable in "${MISSING_EXECUTABLES[@]}"; do
        echo "  - $executable" >&2
    done
    echo "Please install the missing executables and ensure they are available on your PATH." >&2
    exit 1
fi

# Display configuration
echo "Certificate Generation Configuration:"
echo "  User: $HSM_USER"
echo "  Password: [HIDDEN]"
echo "  Label: $LABEL"
echo ""

# Certificate generation logic goes here
echo "Generating certificates..."


# Create the key pair in CloudHSM
CLOUDHSM_CLI_PATH=$(which cloudhsm-cli)
CLOUDHSM_LIB_PATH=$(dirname "$(dirname "$CLOUDHSM_CLI_PATH")")/lib
CLOUDHSM_PKCS11_MODULE="${CLOUDHSM_LIB_PATH}/libcloudhsm_pkcs11.so"
export CLOUDHSM_PIN="${HSM_USER}:${HSM_PASSWORD}"
export CLOUDHSM_ROLE="crypto-user"
ID=`date +%s`

if [ "$(cloudhsm-cli key list --filter="attr.label=${LABEL}:Private" | jq -r '.data.total_key_count')" == "0" ]; then
  echo "No keys found with label '${LABEL}:Private'. Generating new key pair..."
  cloudhsm-cli key generate-asymmetric-pair rsa --public-label "${LABEL}:Public" --private-label "${LABEL}:Private" \
      --public-attributes encrypt=true verify=true wrap=true \
      --private-attributes private=true extractable=true decrypt=true sign=true unwrap=true id=0x${ID} \
      --modulus-size-bits ${KEYSIZE_BITS} --public-exponent 65537
else
  ID=$(cloudhsm-cli key list -v --filter="attr.label=${LABEL}:Private" | jq -r '.data.matched_keys[0].attributes.id' | cut -c 3-)
  echo "Key pair with label '${LABEL}:Private' already exists. Skipping key generation. ID: $ID"
fi

echo "Exporting keys..."
cloudhsm-cli key generate-file --encoding reference-pem --path ${LABEL}.key --filter attr.label="${LABEL}:Private"
cloudhsm-cli key generate-file --encoding pem --path ${LABEL}.pub --filter attr.label="${LABEL}:Public"

echo "Creating a cert using the public key..."
openssl req -engine cloudhsm -x509 -key ${LABEL}.key -out ${LABEL}.pem -sha256 -days 365 -nodes -subj "/CN=${LABEL}"

# Clean up
rm -f ${LABEL}.key ${LABEL}.pub
printf "Certificate generation completed.\n\tID:\t$ID\n\tLabel:\t$LABEL"