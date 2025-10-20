import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { CognitoIdentityProviderClient, InitiateAuthCommand, GetUserCommand } from '@aws-sdk/client-cognito-identity-provider';

const client = new CognitoIdentityProviderClient({});

/**
 * Decode JWT payload (without verification - for extracting claims only)
 * In production, use a proper JWT library with signature verification
 */
function decodeJwtPayload(token: string): any {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }
  const payload = Buffer.from(parts[1], 'base64').toString('utf8');
  return JSON.parse(payload);
}

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

    if (!AuthenticationResult?.AccessToken || !AuthenticationResult?.RefreshToken || !AuthenticationResult?.IdToken) {
      throw new Error('Missing authentication tokens');
    }

    // Decode ID token to extract user claims
    const idTokenPayload = decodeJwtPayload(AuthenticationResult.IdToken);

    // Build user object from ID token claims
    const user = {
      id: idTokenPayload.sub,
      email: idTokenPayload.email,
      firstName: idTokenPayload.given_name || '',
      lastName: idTokenPayload.family_name || '',
    };

    // Return response matching AuthResponse interface
    return {
      statusCode: 200,
      body: JSON.stringify({
        user,
        accessToken: AuthenticationResult.AccessToken,
        refreshToken: AuthenticationResult.RefreshToken,
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