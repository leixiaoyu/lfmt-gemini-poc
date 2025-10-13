import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { CognitoIdentityProviderClient, SignUpCommand } from '@aws-sdk/client-cognito-identity-provider';

const client = new CognitoIdentityProviderClient({});

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    const { email, password, given_name, family_name } = JSON.parse(event.body || '{}');

    if (!email || !password || !given_name || !family_name) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'Missing required fields' }),
      };
    }

    const command = new SignUpCommand({
      ClientId: process.env.COGNITO_CLIENT_ID!,
      Username: email,
      Password: password,
      UserAttributes: [
        {
          Name: 'given_name',
          Value: given_name,
        },
        {
          Name: 'family_name',
          Value: family_name,
        },
      ],
    });

    await client.send(command);

    return {
      statusCode: 201,
      body: JSON.stringify({ message: 'User registered successfully' }),
    };
  } catch (error: any) {
    console.error(error);
    if (error.message.includes('UsernameExistsException')) {
      return {
        statusCode: 409,
        body: JSON.stringify({ message: 'User already exists' }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Internal server error' }),
    };
  }
};