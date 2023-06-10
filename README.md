## golang-sso-server

The SSO server using OIDC authentication in Golang.

### How to use

1. Please set the various information of the external provider as environment variables.
```
export ISSUER=
export CLIENT_ID=
export CLIENT_SECRET=
export REDIRECT_URL=
```

2. start the server.
```
go run main.go
```
