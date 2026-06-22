# auth-firebase

Firebase Authentication driver for togo [auth](https://github.com/togo-framework/auth).
The frontend signs in with the Firebase SDK and POSTs the ID token to the backend,
which verifies it (RS256 against Google certs) and issues a togo session.

```bash
togo install togo-framework/auth
togo install togo-framework/auth-firebase
```

Env: `FIREBASE_PROJECT_ID`. Endpoint: POST `/api/auth/firebase` { id_token }.
