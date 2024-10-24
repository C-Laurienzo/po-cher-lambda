import { CognitoIdentityProviderClient, ResendConfirmationCodeCommand } from "@aws-sdk/client-cognito-identity-provider";
import { createHmac } from "crypto";

const clientSecret = process.env.CLIENT_SECRET;
const clientId = process.env.CLIENT_ID;
const cognito = new CognitoIdentityProviderClient({ region: process.env.REGION });

export const handler = async (event) => {
  const { username } = JSON.parse(event?.body)
  
  const headers = {
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "OPTIONS,POST"
    }

  const getSecretHash = () => {
    const hasher = createHmac("sha256", clientSecret);
    hasher.update(`${username}${clientId}`);

    return hasher.digest("base64");
  }

  const command = new ResendConfirmationCodeCommand({
    ClientId: clientId,
    SecretHash: getSecretHash(),
    Username: username,
  });

  const onSuccess = () => {
    return {
      headers,
      statusCode: 200
    }
  }

  const onError = () => {
    return {
      headers,
      statusCode: 500,
      body: 'Failed resending confirmation code'
    };
  }

  return await cognito.send(command).then(onSuccess).catch(onError);
};
