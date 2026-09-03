export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  try {
    const { url } = req.body || {};

    if (!url || typeof url !== "string") {
      return res.status(400).json({
        error: "أدخل رابطًا صحيحًا"
      });
    }

    let parsed;

    try {
      parsed = new URL(url);
    } catch {
      return res.status(400).json({
        error: "الرابط غير صحيح"
      });
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).json({
        error: "يسمح فقط بروابط HTTP و HTTPS"
      });
    }

    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        error: "VirusTotal API key غير موجودة في Vercel"
      });
    }

    const encodedUrl = Buffer
      .from(url)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    // محاولة الحصول على تقرير سابق للرابط
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
        data: report.data
      });
    }

    // إرسال الرابط للفحص
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
      message: "تم إرسال الرابط للفحص"
    });

  } catch (error) {
    return res.status(500).json({
      error: "حدث خطأ في الخادم",
      details: error.message
    });
  }
}
