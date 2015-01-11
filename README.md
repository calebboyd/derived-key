## derived-key

Generate a secure hash to store secrets (passwords) with

```javascript
import { hash, verify } from 'derived-key'

hash('password',(e,hash) => {
  verify('passwor',hash, (e,same) => {
    console.log(same) //false
  })
})
```

### Building & Testing

`npm install`

`npm test`

`npm run build`