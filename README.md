# TOKEN FINDER
Este é um script em Node.js que escaneia arquivos JavaScript de um site para encontrar tokens sensíveis, como API Keys e JWTs, diretamente no frontend.

O que ele faz:

Acessa um domínio que você escolher
Pega os scripts JavaScript (externos ou inline)
Procura por tokens sensíveis
Mostra onde encontrou cada token, com tipo, valor, arquivo, linha e posição

Uso:
```bash
npm install
```
```bash
node index.js example.com
```
