# Long-Form Translation Service (LFMT) POC

This repository contains the proof-of-concept for a Long-Form Translation Service that translates large documents using the Gemini API.

## Project Overview

The LFMT service is designed to handle the translation of large text documents (65,000 to 400,000 words) by splitting them into smaller chunks, translating each chunk, and then reassembling them into a final translated document.

## Technology Stack

*   **Frontend**: React (Create React App)
*   **Backend**: AWS Serverless (Lambda, API Gateway, Step Functions, S3, DynamoDB)
*   **Infrastructure as Code**: AWS CDK

## Project Structure

The repository is organized into the following directories:

*   `frontend/`: Contains the React frontend application.
*   `backend/`: Contains the AWS serverless backend, including Lambda functions and CDK infrastructure definitions.
*   `shared-types/`: Contains shared TypeScript types used by both the frontend and backend.
*   `scripts/`: Contains utility scripts for deployment and development.

## Getting Started

### Prerequisites

*   Node.js
*   AWS CLI
*   AWS Account

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/lfmt-gemini-poc.git
    ```
2.  Install dependencies for each package:
    ```bash
    npm install --prefix frontend
    npm install --prefix backend/functions
    npm install --prefix backend/infrastructure
    npm install --prefix shared-types
    ```

### Deployment

1.  Configure your AWS credentials.
2.  Deploy the backend infrastructure using the AWS CDK:
    ```bash
    npm run deploy --prefix backend/infrastructure
    ```
3.  Start the frontend development server:
    ```bash
    npm start --prefix frontend
    ```
