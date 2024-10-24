import { CognitoIdentityProviderClient, ConfirmForgotPasswordCommand } from "@aws-sdk/client-cognito-identity-provider";
import { createHmac } from "crypto";

const clientSecret = process.env.CLIENT_SECRET;
const clientId = process.env.CLIENT_ID;
const cognito = new CognitoIdentityProviderClient({ region: process.env.REGION });

export const handler = async (event) => {
  const { username, password, confirmationCode } = JSON.parse(event?.body)
  
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

  const command = new ConfirmForgotPasswordCommand({
    ClientId: clientId,
    SecretHash: getSecretHash(),
    Username: username,
    Password: password,
    ConfirmationCode: confirmationCode,
  });

  const onSuccess = (response) => {
    return {
      headers,
      statusCode: 200,
      body: JSON.stringify(response)
    }
  }

  const onError = (error) => {
    return {
      headers,
      statusCode: 500,
      body: JSON.stringify(error)
    };
  }

  return await cognito.send(command).then(onSuccess).catch(onError);
};