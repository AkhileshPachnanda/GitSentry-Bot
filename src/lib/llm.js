const config = require("../config");
const logger = require("./logger");

async function getRemediation(finding) {
  let prompt = "";
  if (finding.category === "dependency") {
    prompt = `Package: ${finding.package}
Vulnerability: ${finding.title}
Affected: ${finding.vulnerable_versions || "N/A"}
CVE: ${finding.cve || "N/A"}`;
  } else if (finding.category === "secret") {
    const snippet = finding.content ? finding.content.substring(0, 100) : "";
    prompt = `Secret Type: ${finding.type}
File: ${finding.file || "unknown"}
Snippet: ${snippet}`;
  } else {
    prompt = `Type: ${finding.type || finding.category || "Security Finding"}
Details: ${finding.title || finding.message || JSON.stringify(finding)}`;
  }

  const useGroq = !!config.groqApiKey;
  const url = useGroq
    ? "https://api.groq.com/openai/v1/chat/completions"
    : `${config.ollamaApiUrl}/v1/chat/completions`;

  const headers = {
    "Content-Type": "application/json",
  };

  if (useGroq) {
    headers["Authorization"] = `Bearer ${config.groqApiKey}`;
  }

  const model = useGroq ? config.groqModel : config.ollamaModel;

  const body = {
    model,
    messages: [
      {
        role: "system",
        content: "You are a secure coding assistant. Your task is to provide an extremely concise, single-sentence remediation instruction for the security finding. Do not explain the vulnerability, do not write code blocks, do not show example code, and do not provide background information. Output ONLY the single actionable step to fix it.",
      },
      {
        role: "user",
        content: prompt,
      },
    ],
    temperature: 0.1,
  };

  try {
    logger.info(`Requesting LLM remediation for ${finding.package || finding.type || "finding"} via ${useGroq ? "Groq" : "Ollama"}`);
    const response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`LLM API returned status ${response.status}: ${errText}`);
    }

    const data = await response.json();
    const remediation = data.choices?.[0]?.message?.content?.trim();
    if (!remediation) {
      throw new Error("Empty response from LLM API");
    }
    return remediation;
  } catch (error) {
    logger.error("Failed to fetch LLM remediation suggestion", error.message);
    // Return a generic fallback suggestion
    if (finding.category === "dependency") {
      return `Upgrade ${finding.package} to a non-vulnerable version (outside of ${finding.vulnerable_versions || "affected ranges"}) and verify with your dependency lockfile.`;
    }
    if (finding.category === "secret") {
      return `Revoke the exposed credentials immediately, remove them from the commit history, and configure them as GitHub secrets or environment variables.`;
    }
    return `Review the flagged vulnerability and update code/dependencies accordingly to resolve security risks.`;
  }
}

module.exports = { getRemediation };
