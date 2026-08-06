import crypto from "crypto";

function base64url(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function getAccessToken(clientEmail, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(
    JSON.stringify({
      iss: clientEmail,
      scope: "https://www.googleapis.com/auth/analytics.readonly",
      aud: "https://oauth2.googleapis.com/token",
      exp: now + 3600,
      iat: now,
    })
  );

  const signingInput = `${header}.${payload}`;
  const sign = crypto.createSign("RSA-SHA256");
  sign.update(signingInput);
  const signature = sign
    .sign(privateKey, "base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  const jwt = `${signingInput}.${signature}`;

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });

  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) {
    throw new Error("Token exchange failed: " + JSON.stringify(tokenData));
  }
  return tokenData.access_token;
}

async function runReport(accessToken, propertyId, dimensions, metrics, dateRanges, orderBys, limit) {
  const body = { dimensions, metrics, dateRanges };
  if (orderBys) body.orderBys = orderBys;
  if (limit) body.limit = limit;

  const res = await fetch(
    `https://analyticsdata.googleapis.com/v1beta/properties/${propertyId}:runReport`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    }
  );
  return res.json();
}

export const handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method not allowed" };
  }

  let password;
  try {
    ({ password } = JSON.parse(event.body || "{}"));
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: "Bad request" }) };
  }

  if (password !== process.env.ANALYTICS_PASSWORD) {
    return { statusCode: 401, body: JSON.stringify({ error: "Unauthorized" }) };
  }

  const propertyId = process.env.GA_PROPERTY_ID;
  const clientEmail = process.env.GA_CLIENT_EMAIL;
  const privateKey = process.env.GA_PRIVATE_KEY.replace(/\\n/g, "\n");

  let accessToken;
  try {
    accessToken = await getAccessToken(clientEmail, privateKey);
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: "Auth failed: " + e.message }) };
  }

  const orderByMetric = (name) => [{ metric: { metricName: name }, desc: true }];

  try {
    const [totalReport, weekReport, dailyReport, pagesReport, countryReport, cityReport] =
      await Promise.all([
        runReport(accessToken, propertyId, [], [{ name: "totalUsers" }, { name: "sessions" }, { name: "screenPageViews" }], [{ startDate: "2020-01-01", endDate: "today" }]),
        runReport(accessToken, propertyId, [], [{ name: "totalUsers" }, { name: "sessions" }], [{ startDate: "7daysAgo", endDate: "today" }]),
        runReport(accessToken, propertyId, [{ name: "date" }], [{ name: "totalUsers" }], [{ startDate: "30daysAgo", endDate: "today" }], [{ dimension: { dimensionName: "date" }, desc: false }]),
        runReport(accessToken, propertyId, [{ name: "pagePath" }], [{ name: "screenPageViews" }], [{ startDate: "2020-01-01", endDate: "today" }], orderByMetric("screenPageViews"), 20),
        runReport(accessToken, propertyId, [{ name: "country" }], [{ name: "totalUsers" }], [{ startDate: "2020-01-01", endDate: "today" }], orderByMetric("totalUsers"), 20),
        runReport(accessToken, propertyId, [{ name: "city" }], [{ name: "totalUsers" }], [{ startDate: "2020-01-01", endDate: "today" }], orderByMetric("totalUsers"), 20),
      ]);

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ total: totalReport, week: weekReport, daily: dailyReport, pages: pagesReport, countries: countryReport, cities: cityReport }),
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
