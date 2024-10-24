import { CognitoIdentityProviderClient, InitiateAuthCommand, AuthFlowType } from "@aws-sdk/client-cognito-identity-provider";
import { createHmac } from "crypto";

const clientSecret = process.env.CLIENT_SECRET;
const clientId = process.env.CLIENT_ID;
const cognito = new CognitoIdentityProviderClient({ region: process.env.REGION });

export const handler = async (event) => {
  const { refreshToken, userId } = JSON.parse(event?.body)

  const headers = {
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "OPTIONS,POST"
    }

  const getSecretHash = () => {
    const hasher = createHmac("sha256", clientSecret);
    hasher.update(`${userId}${clientId}`);

    return hasher.digest("base64");
  }

  const command = new InitiateAuthCommand({
    AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
    AuthParameters: {
      REFRESH_TOKEN: refreshToken,
      SECRET_HASH: getSecretHash()
    },
    ClientId: clientId,
  });

  const onSuccess = (response) => {
    const { AuthenticationResult } = response;

    return {
      headers,
      statusCode: 200,
      body: JSON.stringify(AuthenticationResult)
    };
  }

  const onError = () => {
    return {
      headers,
      statusCode: 401,
      body: JSON.stringify(`Unauthorized request.`)
    };
  }

  return await cognito.send(command).then(onSuccess).catch(onError);
};
