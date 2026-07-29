import os

from anthropic import Anthropic


def ai_summary(incidents, anomaly_scores, context: str = ""):
    """Generate a 3-sentence SOC executive summary of the incidents via the Claude
    API. Returns None if ANTHROPIC_API_KEY is unset or the response is empty.
    anomaly_scores is accepted for caller parity but isn't used in the prompt.
    context is optional RAG-retrieved threat intel injected before the incident list."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    client = Anthropic(api_key=key)
    inc_text = "\n".join(
        f"- {i['incident_type']} from {i['source_ip']}, "
        f"count={i['event_count']}, MITRE={i.get('mitre',{}).get('id','?')}"
        for i in incidents
    )
    prompt = (
        f"You are a SOC analyst. Write a 3-sentence executive "
        f"summary of these security incidents:\n{inc_text}\n"
        f"Include MITRE technique IDs and remediation advice."
    )
    if context:
        prompt = f"{context}\n\n{prompt}"
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=200,
        messages=[{"role": "user", "content": prompt}],
    )
    if not msg.content:
        return None
    return msg.content[0].text
