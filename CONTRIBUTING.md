# contributing

want to improve `browser-encrypted-vault`? welcome aboard bhai.

## quick setup

```bash
npm install
npm test
npm run typecheck
```

## simple rules

* keep runtime dependencies at zero. use native WebCrypto and browser APIs only.
* never write plain text keys or seed phrases to `localStorage` or `sessionStorage`.
* add a unit test inside `tests/` whenever you touch encryption or log scrubbing.
* run `npm test` and `npm run typecheck` before opening a pull request.
