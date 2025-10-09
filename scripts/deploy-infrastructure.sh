#!/bin/bash

# LFMT Infrastructure Deployment Script
# This script follows best practices by changing into the package directory
# and using npx to run locally installed package binaries.

set -e  # Exit on any error

echo "🚀 LFMT Infrastructure Deployment Script"
echo "======================================="

# Configuration
ENVIRONMENT=${1:-dev}
REGION=${2:-us-east-1}
PROFILE=${3:-default}

echo "📋 Configuration:"
echo "   Environment: $ENVIRONMENT"
echo "   Region: $REGION"
echo "   AWS Profile: $PROFILE"
echo ""

# --- Validation ---
echo "🔐 Validating environment..."
if [[ ! "$ENVIRONMENT" =~ ^(dev|staging|prod)$ ]]; then
    echo "❌ Error: Environment must be one of: dev, staging, prod" >&2
    exit 1
fi

if ! command -v aws &> /dev/null; then
    echo "❌ Error: AWS CLI is required but not installed" >&2
    exit 1
fi

if ! aws sts get-caller-identity --profile $PROFILE &> /dev/null; then
    echo "❌ Error: AWS credentials not configured or invalid for profile '$PROFILE'" >&2
    echo "   Please run: aws configure --profile $PROFILE" >&2
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --profile $PROFILE --query Account --output text)
echo "✅ AWS credentials valid (Account: $ACCOUNT_ID)"

# --- Execution ---

# Get the directory of the current script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Define the path to the infrastructure package
INFRASTRUCTURE_DIR="$SCRIPT_DIR/../backend/infrastructure"

# Change into the infrastructure directory. This is the crucial step.
# All subsequent commands are run from this context.
cd "$INFRASTRUCTURE_DIR"
echo "📁 Changed to infrastructure directory: $(pwd)"

# Install all dependencies defined in package.json (including aws-cdk, @types/node, etc.)
# This will create the local node_modules/.bin directory with our executables.
echo "📦 Installing dependencies..."
mkdir -p .npm-cache
npm install --cache .npm-cache
npm install --cache .npm-cache --prefix "backend/functions/auth" @aws-sdk/client-cognito-identity-provider @types/aws-lambda

# Build the TypeScript code to JavaScript.
# This is a prerequisite for running tests and deploying.
echo "🔨 Building TypeScript..."
npm run build

# Run the unit tests. This acts as a quality gate before deployment.
echo "🧪 Running infrastructure tests..."
npm test

if [ $? -ne 0 ]; then
    echo "❌ Error: Local tests failed. Aborting deployment." >&2
    exit 1
fi

# Synthesize the CloudFormation template. This is a dry run.
echo "🔄 Synthesizing CloudFormation templates..."
npx cdk synth --context environment=$ENVIRONMENT --profile $PROFILE

# Deploy the stack to AWS.
# The --require-approval never flag allows for non-interactive deployment.
echo "🚀 Deploying stack to $ENVIRONMENT..."
npx cdk deploy --context environment=$ENVIRONMENT --profile $PROFILE --require-approval never

echo "✅ Deployment successful!"
