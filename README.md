# JWT (JSON Web Token) İlə Qeydiyyat və Giriş

Bu layihə, istifadəçilərin qeydiyyatdan keçməsi və giriş etməsi üçün JWT (JSON Web Token) istifadə edən bir server tətbiqidir. JWT, istifadəçi autentifikasiyası və məlumat mübadiləsi üçün təhlükəsiz və rahat bir üsuldur.

## :star: Xüsusiyyətlər

- :white_check_mark: İstifadəçi qeydiyyatı
- :key: İstifadəçi girişi
- :lock: JWT yaratmaq və onu cookie-lərə göndərmək
- :shield: Giriş tələb edən səhifələr üçün autentifikasiyanın təmin edilməsi

## :gear: Tələb olunanlar

- **Node.js** və **npm** (Node Package Manager)
- **Express.js**
- **JSON Web Token** (jsonwebtoken paketi)
- **Cookie Parser** (cookie-parser paketi)
- **BcryptJs** (bcrypt paketi)
- **Cors** (cors paketi)
- **BodyParser** (body-parser paketi)
- **mongoose** (mongoose paketi)

## :wrench: Quraşdırma

1. **Bu repozitoriyanı klonlayın:**

   ```bash
   git clone https://github.com/sizin-username/jwt-authentication.git
   cd jwt-authentication
   npm i
   npx nodemon (node app.js)
