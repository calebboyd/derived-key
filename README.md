## derived-key

Generate a secure hash to store secrets (passwords) with

```javascript
import { hash, verify } from 'derived-key'

async function main () {
  const hashed = await hash('password')    
  return verify('passwor', hashed)
}

main().then(x => console.log(x)) //false
```

### Building & Testing

`npm install`

`npm test`

`npm run prepublish`