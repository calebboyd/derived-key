## derived-key

Generate a secure hash to store secrets (passwords) with

```javascript
import { hash, verify } from 'derived-key'

const hash = await hash('password')

const isVerified = await verify('passwor', hash)

console.log(isVerified) //false
```

### Building & Testing

`npm install`

`npm test`

`npm run prepublish`