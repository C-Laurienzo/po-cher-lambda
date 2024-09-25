import { CognitoIdentityProviderClient, GlobalSignOutCommand } from "@aws-sdk/client-cognito-identity-provider";

const cognito = new CognitoIdentityProviderClient({ region: process.env.REGION });

export const handler = async (event) => {
  const headers = {
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "OPTIONS,POST"
  };
  const eventBody = JSON.parse(event?.body)
  const AccessToken = eventBody?.accessToken;

  const command = new GlobalSignOutCommand({
    AccessToken
  });

  const onSuccess = () => {
    return {
      headers,
      statusCode: 200,
      body: JSON.stringify('Success')
    };
  }

  const onError = () => {
    return {
      headers,
      statusCode: 500,
      body: JSON.stringify('Failed')
    };
  }

  return await cognito.send(command).then(onSuccess).catch(onError);
};

