import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { CognitoIdentityProviderClient, InitiateAuthCommand } from '@aws-sdk/client-cognito-identity-provider';

const client = new CognitoIdentityProviderClient({});

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    const { refreshToken } = JSON.parse(event.body || '{}');

    if (!refreshToken) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'Missing refresh token' }),
      };
    }

    const command = new InitiateAuthCommand({
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      ClientId: process.env.COGNITO_CLIENT_ID!,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
      },
    });

    const { AuthenticationResult } = await client.send(command);

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'Token refreshed successfully',
        accessToken: AuthenticationResult?.AccessToken,
        idToken: AuthenticationResult?.IdToken,
      }),
    };
  } catch (error: any) {
    console.error(error);
    if (error.message.includes('NotAuthorizedException')) {
      return {
        statusCode: 401,
        body: JSON.stringify({ message: 'Invalid refresh token' }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Internal server error' }),
    };
  }
};