import os
from anthropic import Anthropic

def ai_summary(incidents, anomaly_scores):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    client = Anthropic(api_key=key)
    inc_text = "\n".join(
        f"- {i['incident_type']} from {i['source_ip']}, "
        f"count={i['event_count']}, MITRE={i.get('mitre',{}).get('id','?')}"
        for i in incidents
    )
    msg = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=200,
        messages=[{"role":"user","content":
            f"You are a SOC analyst. Write a 3-sentence executive "
            f"summary of these security incidents:\n{inc_text}\n"
            f"Include MITRE technique IDs and remediation advice."}]
    )
    return msg.content[0].text
