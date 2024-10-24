import { CognitoIdentityProviderClient, SignUpCommand, UsernameExistsException } from "@aws-sdk/client-cognito-identity-provider";
import { createHmac } from "crypto";

const clientSecret = process.env.CLIENT_SECRET;
const clientId = process.env.CLIENT_ID;
const cognito = new CognitoIdentityProviderClient({ region: process.env.REGION });

export const handler = async (event) => {
  const { email, password, phoneNumber, firstName, lastName } = JSON.parse(event?.body)
  
  const headers = {
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "OPTIONS,POST"
    }

  const getSecretHash = () => {
    const hasher = createHmac("sha256", clientSecret);
    hasher.update(`${email}${clientId}`);

    return hasher.digest("base64");
  }

  const command = new SignUpCommand({
    ClientId: clientId,
    SecretHash: getSecretHash(),
    Username: email,
    Password: password,
    UserAttributes: [
      {
        Name: "phone_number",
        Value: phoneNumber
      },
      {
        Name: "given_name",
        Value: firstName
      },
      {
        Name: "family_name",
        Value: lastName
      }
    ]
  });

  const onSuccess = (response) => {
    return {
      headers,
      statusCode: 200,
      body: JSON.stringify({
        userConfirmed: response?.UserConfirmed,
        deliveryMedium: response?.CodeDeliveryDetails?.DeliveryMedium
      })
    }
  }

  const onError = (error) => {
    let statusCode, body;
    
    if (error instanceof UsernameExistsException) {
      statusCode = 400;
      body = 'User already exists'
    } else {
      statusCode = 500
      body = 'Failed sign up'
    }
    
    return {
      headers,
      statusCode,
      body
    };
  }

  return await cognito.send(command).then(onSuccess).catch(onError);
};