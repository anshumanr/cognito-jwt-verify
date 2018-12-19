# cognito-jwt-verify
Simple custom authorizer for API gateway verifying tokens generated using AWS Cognito Userpools.
In this example, we are expecting 'id_token' to be present in the 'authorizationToken'.

On succesful verification, 'allow' policy is built & returned to API gateway.
