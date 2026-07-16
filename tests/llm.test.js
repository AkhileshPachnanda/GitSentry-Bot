const { getRemediation } = require("../src/lib/llm");
const config = require("../src/config");

describe("LLM Remediation Helper", () => {
  let originalFetch;
  let mockFetch;

  beforeAll(() => {
    originalFetch = globalThis.fetch;
  });

  afterAll(() => {
    globalThis.fetch = originalFetch;
  });

  beforeEach(() => {
    mockFetch = jest.fn();
    globalThis.fetch = mockFetch;
    // Reset configuration values
    config.groqApiKey = "";
    config.groqModel = "llama-3.1-8b-instant";
    config.ollamaApiUrl = "http://localhost:11434";
    config.ollamaModel = "llama3";
  });

  test("uses Groq API when GROQ_API_KEY is configured", async () => {
    config.groqApiKey = "fake-groq-key";
    
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        choices: [
          {
            message: {
              content: "Upgrade lodash to 4.17.21 or later.",
            },
          },
        ],
      }),
    });

    const finding = {
      category: "dependency",
      package: "lodash",
      title: "Prototype Pollution in lodash",
      severity: "high",
      vulnerable_versions: "< 4.17.21",
      cve: "CVE-2020-8203",
      file: "package.json",
    };

    const remediation = await getRemediation(finding);
    expect(remediation).toBe("Upgrade lodash to 4.17.21 or later.");
    expect(mockFetch).toHaveBeenCalledTimes(1);
    
    const [calledUrl, calledOptions] = mockFetch.mock.calls[0];
    expect(calledUrl).toBe("https://api.groq.com/openai/v1/chat/completions");
    expect(calledOptions.headers["Authorization"]).toBe("Bearer fake-groq-key");
    
    const body = JSON.parse(calledOptions.body);
    expect(body.model).toBe("llama-3.1-8b-instant");
    const userMsg = body.messages.find(m => m.role === "user").content;
    expect(userMsg).toContain("Package: lodash");
  });

  test("uses Ollama local API when GROQ_API_KEY is NOT configured", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        choices: [
          {
            message: {
              content: "Revoke key and store in environment variable.",
            },
          },
        ],
      }),
    });

    const finding = {
      category: "secret",
      type: "Slack Webhook URL",
      file: "config.js",
      line: 12,
      content: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    };

    const remediation = await getRemediation(finding);
    expect(remediation).toBe("Revoke key and store in environment variable.");
    expect(mockFetch).toHaveBeenCalledTimes(1);
    
    const [calledUrl, calledOptions] = mockFetch.mock.calls[0];
    expect(calledUrl).toBe("http://localhost:11434/v1/chat/completions");
    expect(calledOptions.headers["Authorization"]).toBeUndefined();
    
    const body = JSON.parse(calledOptions.body);
    expect(body.model).toBe("llama3");
    const userMsg = body.messages.find(m => m.role === "user").content;
    expect(userMsg).toContain("Secret Type: Slack Webhook URL");
  });

  test("handles unknown finding categories gracefully", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        choices: [
          {
            message: {
              content: "Fix the custom issue.",
            },
          },
        ],
      }),
    });

    const finding = {
      category: "custom",
      type: "custom-vulnerability",
      title: "Some custom issue description",
    };

    const remediation = await getRemediation(finding);
    expect(remediation).toBe("Fix the custom issue.");
    expect(mockFetch).toHaveBeenCalledTimes(1);
    
    const [, calledOptions] = mockFetch.mock.calls[0];
    const body = JSON.parse(calledOptions.body);
    const userMsg = body.messages.find(m => m.role === "user").content;
    expect(userMsg).toContain("Type: custom-vulnerability");
  });

  test("falls back to generic dependency suggestion on API error or fail (missing vulnerable_versions)", async () => {
    mockFetch.mockRejectedValueOnce(new Error("Network Error"));

    const finding = {
      category: "dependency",
      package: "lodash",
    };

    const remediation = await getRemediation(finding);
    expect(remediation).toContain("Upgrade lodash to a non-vulnerable version (outside of affected ranges)");
  });

  test("falls back to generic secret suggestion on API error or fail", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      text: async () => "Internal Server Error",
    });

    const finding = {
      category: "secret",
      type: "AWS Access Key",
    };

    const remediation = await getRemediation(finding);
    expect(remediation).toContain("Revoke the exposed credentials immediately");
  });

  test("falls back to generic suggestion for other category on API error or fail", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}), // Missing choices
    });

    const finding = {
      category: "other",
    };

    const remediation = await getRemediation(finding);
    expect(remediation).toContain("Review the flagged vulnerability");
  });

  test("handles unknown finding category without title but with message or full json", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        choices: [
          {
            message: {
              content: "Fix the custom issue.",
            },
          },
        ],
      }),
    });

    const finding = {
      category: "custom",
      message: "custom message",
    };

    await getRemediation(finding);
    const [, calledOptions] = mockFetch.mock.calls[0];
    const body = JSON.parse(calledOptions.body);
    const userMsg = body.messages.find(m => m.role === "user").content;
    expect(userMsg).toContain("Details: custom message");

    mockFetch.mockClear();

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        choices: [{ message: { content: "Fix it." } }],
      }),
    });

    const finding2 = {
      category: "custom",
    };

    await getRemediation(finding2);
    const [, calledOptions2] = mockFetch.mock.calls[0];
    const body2 = JSON.parse(calledOptions2.body);
    const userMsg2 = body2.messages.find(m => m.role === "user").content;
    expect(userMsg2).toContain('Details: {"category":"custom"}');

    mockFetch.mockClear();

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        choices: [{ message: { content: "Fix it." } }],
      }),
    });

    const finding3 = {
      title: "no category or type",
    };

    await getRemediation(finding3);
    const [, calledOptions3] = mockFetch.mock.calls[0];
    const body3 = JSON.parse(calledOptions3.body);
    const userMsg3 = body3.messages.find(m => m.role === "user").content;
    expect(userMsg3).toContain('Type: Security Finding');
  });

  test("config helper getNumberEnv handles non-finite inputs", () => {
    process.env.PORT = "not-a-number";
    // We re-require config to trigger the module load with new env, but config is cached.
    // So let's delete it from cache first.
    delete require.cache[require.resolve("../src/config")];
    const configReloaded = require("../src/config");
    expect(configReloaded.port).toBe(3000);
    delete process.env.PORT;
  });
});
