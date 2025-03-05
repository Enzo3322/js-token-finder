const axios = require("axios");
const cheerio = require("cheerio");
const url = require("url");
const path = require("path");

class TokenScanner {
  constructor() {
    this.tokenPatterns = {
      "API Key": /(?:api[_-]?key|API[_-]?KEY)[=:"'\s]+([a-zA-Z0-9\-_]{20,})/gi,
      JWT: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/gi,
      "AWS Key": /AKIA[0-9A-Z]{16}/gi,
      "Generic Token":
        /(?:token|TOKEN|auth|AUTH)[=:"'\s]+([a-zA-Z0-9\-_]{20,})/gi,
      "Bearer Token": /bearer\s+[a-zA-Z0-9\-_\.]{20,}/gi,
    };

    this.headers = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    };
  }

  getFileNameFromUrl(scriptUrl) {
    try {
      const parsedUrl = new URL(scriptUrl);
      return path.basename(parsedUrl.pathname) || "unknown.js";
    } catch {
      return "unknown.js";
    }
  }

  scanContent(content, source) {
    const findings = [];
    const fileName = source.includes("(inline)")
      ? "inline_script"
      : this.getFileNameFromUrl(source);

    for (const [type, pattern] of Object.entries(this.tokenPatterns)) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const lines = content.substring(0, match.index).split("\n");
        findings.push({
          type,
          value: match[0],
          line: lines.length,
          position: match.index,
          source,
          fileName,
        });
      }
    }

    return findings;
  }

  async fetchAndScan(domain) {
    const results = {};

    try {
      const response = await axios.get(domain, { headers: this.headers });
      const $ = cheerio.load(response.data);

      const scriptPromises = [];
      $("script").each((_, element) => {
        const src = $(element).attr("src");
        const inlineContent = $(element).html();

        if (src) {
          const jsUrl = url.resolve(domain, src);
          scriptPromises.push(
            axios
              .get(jsUrl, { headers: this.headers })
              .then((jsResponse) => {
                const findings = this.scanContent(jsResponse.data, jsUrl);
                if (findings.length) results[jsUrl] = findings;
              })
              .catch((err) =>
                console.error(`Erro ao baixar ${jsUrl}: ${err.message}`)
              )
          );
        } else if (inlineContent) {
          const findings = this.scanContent(
            inlineContent,
            `${domain} (inline)`
          );
          if (findings.length) results[`${domain} (inline)`] = findings;
        }
      });

      await Promise.all(scriptPromises);
    } catch (error) {
      console.error(`Erro ao acessar o domínio ${domain}: ${error.message}`);
    }

    return results;
  }

  printResults(results) {
    if (Object.keys(results).length === 0) {
      console.log("Nenhum token potencial encontrado.");
      return;
    }

    for (const [source, findings] of Object.entries(results)) {
      console.log(`\nFonte: ${source}`);
      console.log("-".repeat(50));
      findings.forEach((finding) => {
        console.log(`Tipo: ${finding.type}`);
        console.log(`Valor: ${finding.value}`);
        console.log(`Arquivo: ${finding.fileName}`);
        console.log(`Linha: ${finding.line}`);
        console.log(`Posição: ${finding.position}`);
        console.log("-".repeat(60));
      });
    }
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 1) {
    console.error("Uso: node index.js <dominio>");
    process.exit(1);
  }

  let domain = args[0];
  if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
    domain = `https://${domain}`;
  }

  const scanner = new TokenScanner();
  console.log(`Iniciando scan no domínio: ${domain}`);
  const results = await scanner.fetchAndScan(domain);
  scanner.printResults(results);
}

main().catch(console.error);
