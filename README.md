<!-- togo-brand -->
<p align="center">
  <img src=".github/assets/togo-mark.svg" width="96" alt="togo" />
</p>
<h1 align="center">auth-firebase</h1>
<p align="center"><sub>part of the <a href="https://github.com/togo-framework">togo-framework</a> — the full-stack Go + React framework</sub></p>

Firebase Authentication driver for togo [auth](https://github.com/togo-framework/auth).
The frontend signs in with the Firebase SDK and POSTs the ID token to the backend,
which verifies it (RS256 against Google certs) and issues a togo session.

```bash
togo install togo-framework/auth
togo install togo-framework/auth-firebase
```

Env: `FIREBASE_PROJECT_ID`. Endpoint: POST `/api/auth/firebase` { id_token }.


---

## 💎 Premium sponsors

togo is proudly sponsored by **ID8 Media** and **One Studio**.

<p align="center">
  <a href="https://id8media.com"><img src=".github/assets/id8media.svg" height="44" alt="ID8 Media" /></a>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://one-studio.co"><img src=".github/assets/one-studio.jpeg" height="44" alt="One Studio" /></a>
</p>
