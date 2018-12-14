const jwt = require('jsonwebtoken')
const jwksClient = require('jwks-rsa')
const chalk = require('chalk')
const ora = require('ora')
const spinner = ora('Loading signature key and verifying').start()

const token = require('./token.js')

const colors = ['#f99266', '#fbb773', '#fbcc86', '#f6e57d', '#ccee82']
const randomColor = str => chalk.hex(colors[Math.floor(Math.random() * 5)])(str)

// This should be cached a while. jwks is not updated very often by the identity provider
// Calling this each time verifying a token will cause unnecessary traffic to HID
// Should be set up in the functions index file, if not this might be recreated on each call anyways and the cache will be very effective
const client = jwksClient({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 10, // Default value
  cacheMaxEntries: 5, // Default value
  cacheMaxAge: 36000000, // 10hours, Default value
  jwksUri: 'https://hid.dev-hafslundnett.io/.well-known/openid-configuration/jwks'
})

// This function is called internally by jwt.verify
// Gets the signing key from HID in order to be able to verify the given token
function getKey (header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) {
      console.log('Error getting signing key: ', err.message)
      return
    }
    const signingKey = key.publicKey || key.rsaPublicKey
    setTimeout(() => callback(null, signingKey), 2000)
  })
}

// Tokens from HID are signed with RS256 algorithm
const opts = {
  algorithms: ['RS256']
}

// Verify token (id_token is the one containing bankid_pid, not access_token)
jwt.verify(token, getKey, opts, function (err, decoded) {
  if (err) {
    spinner.fail('Failed token verification')
    console.log('Error: ', err.message)
    return
  }

  spinner.succeed('Verified successfully')
  console.log(chalk.blue`Auth time: `, new Date(decoded.auth_time * 1000))
  console.log(chalk.blue`Expires: `, new Date(decoded.exp * 1000))
  console.log(
    chalk.blue`Scopes: `,
    decoded.scope ? decoded.scope.map(scope => randomColor(scope)).join(' ') : 'no scopes on id_token'
  )
  console.log(chalk.blue`HID ID: `, decoded.sub)
  console.log(chalk.blue`Identity provider: `, decoded.idp)
  console.log(chalk.blue`Issued by: `, decoded.iss)
  console.log(chalk.blue`BankID PID: `, decoded.bankid_pid)
})
