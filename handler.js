const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const request = require('request');

const tokenType = 'id';

exports.handler = async (event) => {

    console.log(JSON.stringify(event));

    let pem;
    const authorizationToken = event.authorizationToken;
    const header = JSON.parse(Buffer.from(authorizationToken.split('.')[0], 'base64'));
    const kid = header.kid;
    const body = JSON.parse(Buffer.from(authorizationToken.split('.')[1], 'base64'));
    const jwkUrl = body.iss + '/.well-known/jwks.json';

    if (body.token_use != tokenType) {
        return buildPolicy(event, 'Deny');
    }

    try {

        console.log(jwkUrl);

        let keys = {};

        await new Promise((resolve, reject) => {
            request(jwkUrl, function (error, response, body) {
                if (error) {
                    console.log('error:', error); // Print the error if one occurred
                    reject(error);
                }

                console.log('body:', body); // Print the HTML for the Google homepage.
                keys = JSON.parse(body);
                resolve();
            });
        });

        for (let key of keys.keys) {
            console.log(key.kid);
            if (key.kid == kid) {
                pem = jwkToPem(key);
                break;
            }
        }

        let verifiedJwt = await jwt.verify(authorizationToken, pem);

        console.log('Success:' + JSON.stringify(verifiedJwt));

        return buildPolicy(event, 'Allow');
    }
    catch(err) {
        console.log(`Error: ${err}`);
        return buildPolicy(event, 'Deny');
    }
};

function buildPolicy(event, effect) {
    let policy = {};

    policy.principalId = '*';
    policy.policyDocument = {};
    policy.policyDocument.Version = "2012-10-17";
    policy.policyDocument.Statement = [
        {
            "Action": "execute-api:Invoke",
            "Effect": effect,
            "Resource": event.methodArn,
        }
    ];
    console.log(JSON.stringify(policy));

    return policy;
}
