// Checks that NEAR_AI_API_KEY works before the agent uses it (M19). The key is read from the
// environment and never printed. Step 1 lists the models (costs nothing); step 2 sends one tiny
// chat request (costs a fraction of a cent) to prove the key can actually call a model.
const key = process.env.NEAR_AI_API_KEY;
const model = process.env.NEAR_AI_MODEL || 'openai/gpt-5-mini';
if (!key) { console.error('NEAR_AI_API_KEY is not set'); process.exit(1); }
const base = 'https://cloud-api.near.ai/v1';
const headers = { 'content-type': 'application/json', authorization: `Bearer ${key}` };

const m = await fetch(`${base}/models`, { headers });
const models = m.ok ? (await m.json()).data.map((x) => x.id) : [];
console.log(`1. GET /models -> HTTP ${m.status}; ${models.length} models; ${model} available: ${models.includes(model)}`);
if (!m.ok) process.exit(1);

const c = await fetch(`${base}/chat/completions`, { method: 'POST', headers,
  body: JSON.stringify({ model, messages: [{ role: 'user', content: 'Answer with the single word: ok' }] }) });
const j = await c.json();
console.log(`2. POST /chat/completions (${model}) -> HTTP ${c.status}; answer: ${JSON.stringify(j.choices?.[0]?.message?.content ?? j.error ?? j).slice(0, 80)}; tokens used: ${j.usage?.total_tokens ?? '?'}`);
process.exit(c.ok ? 0 : 1);
