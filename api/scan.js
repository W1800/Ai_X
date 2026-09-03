import dns from "node:dns/promises";
import https from "node:https";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { url } = req.body || {};

    if (!url || typeof url !== "string") {
      return res.status(400).json({ error: "أدخل رابطًا صحيحًا" });
    }

    let parsed;

    try {
      parsed = new URL(url.trim());
    } catch {
      return res.status(400).json({ error: "الرابط غير صحيح" });
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).json({
        error: "يجب استخدام HTTP أو HTTPS"
      });
    }

    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        error: "VirusTotal API key غير موجودة في Vercel"
      });
    }

    const checks = {
      https: {
        enabled: parsed.protocol === "https:",
        status: parsed.protocol === "https:" ? "جيد" : "تحذير"
      },

      punycode: {
        detected:
          parsed.hostname.includes("xn--") ||
          /[^\x00-\x7F]/.test(parsed.hostname),
        status: "غير مكتمل"
      },

      hostname: {
        value: parsed.hostname,
        levels: parsed.hostname.split(".").length
      },

      shortener: {
        detected: false,
        provider: null
      },

      dns: {
        resolved: false,
        addresses: []
      },

      redirects: {
        detected: false,
        finalUrl: null
      },

      certificate: {
        checked: false,
        valid: null,
        issuer: null,
        subject: null,
        expires: null
      }
    };

    // فحص روابط الاختصار المعروفة
    const shorteners = {
      "bit.ly": "Bitly",
      "tinyurl.com": "TinyURL",
      "t.co": "X/Twitter",
      "goo.gl": "Google",
      "is.gd": "is.gd",
      "cutt.ly": "Cuttly",
      "shorturl.at": "ShortURL",
      "ow.ly": "Ow.ly",
      "buff.ly": "Buff.ly",
      "rebrand.ly": "Rebrandly"
    };

    const host = parsed.hostname.toLowerCase();

    for (const domain of Object.keys(shorteners)) {
      if (host === domain || host.endsWith("." + domain)) {
        checks.shortener.detected = true;
        checks.shortener.provider = shorteners[domain];
        break;
      }
    }

    // فحص DNS
    try {
      const addresses = await dns.lookup(host, {
        all: true
      });

      checks.dns.resolved = addresses.length > 0;
      checks.dns.addresses = addresses.map(x => x.address);
    } catch {
      checks.dns.resolved = false;
    }

    // فحص HTTPS والشهادة
    if (parsed.protocol === "https:") {
      try {
        const certificate = await getCertificate(
          parsed.hostname,
          parsed.port || 443
        );

        if (certificate) {
          checks.certificate.checked = true;
          checks.certificate.valid = true;
          checks.certificate.issuer =
            certificate.issuer?.O ||
            certificate.issuer?.CN ||
            null;

          checks.certificate.subject =
            certificate.subject?.CN ||
            null;

          checks.certificate.expires =
            certificate.valid_to || null;
        }
      } catch {
        checks.certificate.checked = true;
        checks.certificate.valid = false;
      }
    }

    // فحص التحويلات
    try {
      const redirectResponse = await fetch(url, {
        method: "HEAD",
        redirect: "follow"
      });

      checks.redirects.finalUrl = redirectResponse.url || url;
      checks.redirects.detected =
        redirectResponse.url &&
        redirectResponse.url !== url;
    } catch {
      checks.redirects.finalUrl = null;
    }

    // تحويل الرابط إلى ID الخاص بـ VirusTotal
    const encodedUrl = Buffer
      .from(url)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    // محاولة الحصول على تقرير موجود مسبقًا
    const existing = await fetch(
      `https://www.virustotal.com/api/v3/urls/${encodedUrl}`,
      {
        headers: {
          "x-apikey": apiKey
        }
      }
    );

    if (existing.ok) {
      const report = await existing.json();

      return res.status(200).json({
        type: "report",
        data: report.data,
        securityChecks: checks,
        verdict: calculateVerdict(
          report.data?.attributes?.last_analysis_stats,
          checks
        )
      });
    }

    // إرسال الرابط لفحص جديد
    const form = new URLSearchParams();
    form.append("url", url);

    const scan = await fetch(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers: {
          "x-apikey": apiKey,
          "content-type": "application/x-www-form-urlencoded"
        },
        body: form.toString()
      }
    );

    if (!scan.ok) {
      const errorText = await scan.text();

      return res.status(scan.status).json({
        error: "فشل إرسال الرابط إلى VirusTotal",
        details: errorText
      });
    }

    const scanData = await scan.json();

    return res.status(200).json({
      type: "analysis",
      id: scanData.data.id,
      message: "تم إرسال الرابط للفحص",
      securityChecks: checks,
      verdict: "unknown"
    });

  } catch (error) {
    return res.status(500).json({
      error: "حدث خطأ في الخادم",
      details: error.message
    });
  }
}


// فحص شهادة HTTPS
function getCertificate(hostname, port) {
  return new Promise((resolve, reject) => {
    const socket = https.connect({
      host: hostname,
      port: port,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 8000
    });

    socket.on("secureConnect", () => {
      try {
        const certificate = socket.getPeerCertificate();

        socket.end();
        resolve(certificate);
      } catch (error) {
        socket.destroy();
        reject(error);
      }
    });

    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("Certificate timeout"));
    });

    socket.on("error", reject);
  });
}


// تحديد الحالة العامة
function calculateVerdict(stats, checks) {
  if (!stats) {
    return "unknown";
  }

  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;

  if (malicious > 0) {
    return "dangerous";
  }

  if (
    suspicious > 0 ||
    checks.punycode.detected ||
    !checks.dns.resolved ||
    checks.certificate.valid === false
  ) {
    return "suspicious";
  }

  return "safe";
}
