import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { CognitoIdentityProviderClient, InitiateAuthCommand } from '@aws-sdk/client-cognito-identity-provider';

const client = new CognitoIdentityProviderClient({});

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    const { email, password } = JSON.parse(event.body || '{}');

    if (!email || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'Missing required fields' }),
      };
    }

    const command = new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: process.env.COGNITO_CLIENT_ID!,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
      },
    });

    const { AuthenticationResult } = await client.send(command);

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'User logged in successfully',
        accessToken: AuthenticationResult?.AccessToken,
        refreshToken: AuthenticationResult?.RefreshToken,
        idToken: AuthenticationResult?.IdToken,
      }),
    };
  } catch (error: any) {
    console.error(error);
    if (error.message.includes('NotAuthorizedException') || error.message.includes('UserNotFoundException')) {
      return {
        statusCode: 401,
        body: JSON.stringify({ message: 'Incorrect email or password' }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Internal server error' }),
    };
  }
};