## derived-key

Generate a secure (one-way) hash to store secrets with

```javascript
import { hash, verify } from 'derived-key'

async function main () {
  const hashed = await hash('password')    
  return verify('password', hashed)
}

main().then(x => console.log(x)) //true
```

### Building & Testing

`npm i`

`npm run watch`