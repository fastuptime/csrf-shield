# 🚀 `csrf-shield` - CSRF Koruma Middleware'i

`csrf-shield`, web uygulamalarını Cross-Site Request Forgery (CSRF) saldırılarından koruyan bir middleware'dir. Express.js ile kolayca entegre edilir ve formlarınızın ve isteklerinizin güvenliğini sağlar.

## 📦 Kurulum

`csrf-shield` modülünü npm veya Yarn ile projenize ekleyebilirsiniz.

### NPM

```bash
npm install csrf-shield
```

### Yarn

```bash
yarn add csrf-shield
```

## 🛠️ Kullanım

### Temel Kurulum

`csrf-shield`'i Express.js uygulamanıza nasıl entegre edeceğinizle ilgili adım adım bir kılavuz:

1. **Temel bir Express.js uygulaması oluşturun.**

2. **CSRF koruma middleware'ini entegre edin.**

3. **Formlarınızda CSRF token'ını kullanın ve sunucu tarafında doğrulayın.**

### Örnek Kod

Aşağıda, `csrf-shield`'in Express.js uygulamanızda nasıl kullanılacağına dair tam bir örnek verilmiştir:

```javascript
const express = require('express');
const csrfProtection = require('csrf-shield')({
    secret: 'your_secret_key', // Opsiyonel: Şifreleme için özel bir gizli anahtar belirleyin
    timeout: 1000 * 60 * 10, // Opsiyonel: Token geçerlilik süresi (10 dakika)
});
const bodyParser = require('body-parser');

const app = express();

// Form ve JSON verilerini işlemek için body-parser middleware'ini kullanın
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// CSRF koruma middleware'ini uygulayın
app.use(csrfProtection.middleware);

app.get('/', (req, res) => {
    res.send(`
        <form method="post" action="/login">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
            <button type="submit">Login</button>
        </form>
    `);
});

app.post('/login', csrfProtection.verifyToken(), (req, res) => {
    res.send('Giriş yapıldı');
});

app.listen(3000, () => {
    console.log('Sunucu http://localhost:3000 adresinde çalışıyor');
});
```

### Ana Noktalar:

- **`secret`**: (Opsiyonel) CSRF token'larını şifrelemek için kullanılan gizli anahtar. Güvenli bir anahtar belirlemeniz önerilir. Belirtilmezse, varsayılan olarak rastgele bir anahtar oluşturulur.
- **`timeout`**: (Opsiyonel) Token'ların geçerlilik süresi milisaniye cinsinden. Varsayılan olarak 10 dakikadır. Güvenlik ihtiyaçlarınıza göre bu değeri ayarlayabilirsiniz.

### CSRF Token'ları Oluşturma

CSRF token'larını oluşturmak için aşağıdaki yöntemi kullanabilirsiniz:

```javascript
app.use((req, res, next) => {
    req.csrfToken = () => {
        const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip;
        const userAgent = req.headers['user-agent'];
        return csrfProtection.generateToken(ip, userAgent);
    };
    next();
});
```

### Token Doğrulama

Token'ları doğrulamak için `verifyToken` middleware'ini kullanabilirsiniz:

```javascript
app.post('/login', csrfProtection.verifyToken(), (req, res) => {
    res.send('Giriş yapıldı');
});
```

## 🔍 Özellikler

- **Otomatik Token Oluşturma**: Her istek için geçerli bir CSRF token oluşturur.
- **Token Doğrulama**: İsteklerdeki token'ları doğrular ve geçerlilik süresini kontrol eder.
- **Özelleştirilebilir**: Kendi gizli anahtarınızı ve token geçerlilik sürenizi ayarlayabilirsiniz.

## ⚠️ Neden Kullanmalısınız?

CSRF saldırıları, kötü niyetli kullanıcıların bir kullanıcının oturumunu kullanarak istenmeyen işlemler yapmasına olanak tanır. `csrf-shield`, bu tür saldırılara karşı güçlü bir koruma sağlar ve web uygulamanızın güvenliğini artırır.

## 📄 API Referansı

### `csrfShield(options)`

- **options.secret**: (Opsiyonel) Token'ları şifrelemek için kullanılan gizli anahtar. Belirtilmezse, varsayılan olarak rastgele bir anahtar kullanılır.
- **options.timeout**: (Opsiyonel) Token'ların geçerlilik süresi milisaniye cinsinden. Varsayılan olarak 10 dakikadır.

### `middleware(req, res, next)`

- **req.csrfToken()**: Yeni bir CSRF token'ı oluşturur.

### `verifyToken()`

- **req.body._csrf**: (Opsiyonel) Token'ın form verilerinde bulunduğu yer.
- **req.query._csrf**: (Opsiyonel) Token'ın query parametrelerinde bulunduğu yer.
- **req.headers['x-csrf-token']**: (Opsiyonel) Token'ın HTTP başlıklarında bulunduğu yer.

## 🛠️ Destek & Katkı

Herhangi bir sorunla karşılaşırsanız veya katkıda bulunmak isterseniz, lütfen [GitHub deposunu](https://github.com/fastuptime/csrf-shield) ziyaret edin.

## 📝 Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.