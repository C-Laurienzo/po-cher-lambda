import { CognitoIdentityProviderClient, InitiateAuthCommand, AuthFlowType } from "@aws-sdk/client-cognito-identity-provider";
import { createHmac } from "crypto";

const clientSecret = process.env.CLIENT_SECRET;
const clientId = process.env.CLIENT_ID;
const cognito = new CognitoIdentityProviderClient({ region: process.env.REGION });

export const handler = async (event) => {
  const username = event["username"];
  const password = event["password"];

  const getSecretHash = () => {
    const hasher = createHmac("sha256", clientSecret);
    hasher.update(`${username}${clientId}`);

    return hasher.digest("base64");
  }

  const command = new InitiateAuthCommand({
    AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password,
      SECRET_HASH: getSecretHash()
    },
    ClientId: clientId,
  });

  const onSuccess = (response) => {
    let statusCode, body;

    if (response.ChallengeName) {
      const { ChallengeName, ChallengeParameters, Session } = response;

      statusCode = 202;
      body = JSON.stringify({
        ChallengeName,
        ChallengeParameters,
        Session
      });
    }
    else {
      const { AuthenticationResult } = response;
      
      statusCode = 201;
      body = JSON.stringify(AuthenticationResult)
    }

    return {
      statusCode,
      body
    };
  }

  const onError = () => {
    return {
      statusCode: 401,
      body: JSON.stringify("Incorrect username or password.")
    };
  }

  return await cognito.send(command).then(onSuccess).catch(onError);
};
