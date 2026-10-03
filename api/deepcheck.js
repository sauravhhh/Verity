/* Vercel serverless function: pixel-level AI-image deep check via Sightengine.
   Keeps the Sightengine api_secret server-side. Expects raw image bytes
   POSTed with the image's Content-Type. */
module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'POST only' });
    return;
  }
  var user = process.env.SIGHTENGINE_USER;
  var secret = process.env.SIGHTENGINE_SECRET;
  if (!user || !secret) {
    res.status(500).json({ error: 'not_configured' });
    return;
  }
  var chunks = [];
  try {
    for await (const c of req) chunks.push(c);
  } catch (e) {
    res.status(400).json({ error: 'bad_body' });
    return;
  }
  var buf = Buffer.concat(chunks);
  if (!buf.length || buf.length > 10 * 1024 * 1024) {
    res.status(400).json({ error: 'bad_image' });
    return;
  }
  var contentType = req.headers['content-type'] || 'image/png';
  if (!/^image\//.test(contentType)) {
    res.status(400).json({ error: 'bad_image' });
    return;
  }
  try {
    var form = new FormData();
    form.append('media', new Blob([buf], { type: contentType }), 'image');
    form.append('models', 'genai');
    form.append('api_user', user);
    form.append('api_secret', secret);
    var r = await fetch('https://api.sightengine.com/1.0/check.json', {
      method: 'POST',
      body: form
    });
    var data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    res.status(502).json({ error: 'upstream_failed' });
  }
};

module.exports.config = { api: { bodyParser: false } };
