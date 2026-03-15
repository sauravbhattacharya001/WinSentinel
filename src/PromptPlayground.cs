namespace Prompt
{
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using System.Text.RegularExpressions;

    /// <summary>
    /// Entry describing a template in the playground.
    /// </summary>
    public class PlaygroundEntry
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = "";

        [JsonPropertyName("template")]
        public string Template { get; set; } = "";

        [JsonPropertyName("defaults")]
        public Dictionary<string, string> Defaults { get; set; } = new();

        [JsonPropertyName("description")]
        public string Description { get; set; } = "";
    }

    /// <summary>
    /// Generates a self-contained interactive HTML page for testing and
    /// experimenting with prompt templates. Users can fill in variables,
    /// see live previews, copy rendered prompts, and switch between templates.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The generated HTML is fully standalone — no external dependencies,
    /// no server required. Just open in a browser.
    /// </para>
    /// <para>
    /// Example usage:
    /// <code>
    /// var playground = new PromptPlayground();
    /// playground.AddTemplate("greeting",
    ///     "Hello {{name}}, welcome to {{place}}!",
    ///     new Dictionary&lt;string, string&gt; { ["place"] = "the playground" },
    ///     "A simple greeting template");
    /// await playground.SaveAsync("playground.html");
    /// </code>
    /// </para>
    /// </remarks>
    public class PromptPlayground
    {
        private static readonly Regex VariablePattern =
            new(@"\{\{(\w+)\}\}", RegexOptions.Compiled, TimeSpan.FromMilliseconds(500));

        private readonly List<PlaygroundEntry> _entries = new();

        /// <summary>Title displayed in the playground page.</summary>
        public string Title { get; set; } = "Prompt Playground";

        /// <summary>Whether to include a dark mode toggle. Default true.</summary>
        public bool EnableDarkMode { get; set; } = true;

        /// <summary>Number of templates currently registered.</summary>
        public int Count => _entries.Count;

        /// <summary>
        /// Add a template to the playground.
        /// </summary>
        /// <param name="name">Display name for the template.</param>
        /// <param name="template">Template string with {{variable}} placeholders.</param>
        /// <param name="defaults">Optional default values for variables.</param>
        /// <param name="description">Optional description shown in the UI.</param>
        /// <exception cref="ArgumentException">Thrown when name or template is empty.</exception>
        public void AddTemplate(string name, string template,
            Dictionary<string, string>? defaults = null, string description = "")
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Name cannot be empty.", nameof(name));
            if (string.IsNullOrWhiteSpace(template))
                throw new ArgumentException("Template cannot be empty.", nameof(template));

            _entries.Add(new PlaygroundEntry
            {
                Name = name,
                Template = template,
                Defaults = defaults ?? new Dictionary<string, string>(),
                Description = description
            });
        }

        /// <summary>
        /// Add a <see cref="PromptTemplate"/> instance to the playground.
        /// </summary>
        public void AddTemplate(string name, PromptTemplate promptTemplate, string description = "")
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Name cannot be empty.", nameof(name));
            ArgumentNullException.ThrowIfNull(promptTemplate);

            _entries.Add(new PlaygroundEntry
            {
                Name = name,
                Template = promptTemplate.Template,
                Defaults = new Dictionary<string, string>(promptTemplate.Defaults),
                Description = description
            });
        }

        /// <summary>
        /// Import all templates from a <see cref="PromptLibrary"/>.
        /// </summary>
        public void ImportFromLibrary(PromptLibrary library)
        {
            ArgumentNullException.ThrowIfNull(library);
            foreach (var name in library.ListTemplates())
            {
                var template = library.GetTemplate(name);
                if (template != null)
                {
                    AddTemplate(name, template, $"Imported from library");
                }
            }
        }

        /// <summary>
        /// Generate the complete HTML page as a string.
        /// </summary>
        public string GenerateHtml()
        {
            var entriesJson = JsonSerializer.Serialize(_entries, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            var titleEscaped = System.Net.WebUtility.HtmlEncode(Title);

            return $@"<!DOCTYPE html>
<html lang=""en"">
<head>
<meta charset=""UTF-8"">
<meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
<title>{titleEscaped}</title>
<style>
:root {{
  --bg: #ffffff; --fg: #1a1a2e; --card: #f8f9fa; --border: #dee2e6;
  --accent: #4361ee; --accent-hover: #3a56d4; --input-bg: #ffffff;
  --highlight: #fff3cd; --code-bg: #e9ecef; --shadow: rgba(0,0,0,0.08);
}}
.dark {{
  --bg: #0f0f23; --fg: #e0e0e0; --card: #1a1a2e; --border: #2d2d44;
  --accent: #6c83f7; --accent-hover: #8da0ff; --input-bg: #16162b;
  --highlight: #3d3500; --code-bg: #1e1e3a; --shadow: rgba(0,0,0,0.3);
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--bg); color: var(--fg); transition: all 0.3s; }}
.container {{ max-width: 960px; margin: 0 auto; padding: 24px; }}
header {{ display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 24px; padding-bottom: 16px; border-bottom: 2px solid var(--border); }}
h1 {{ font-size: 1.8rem; }}
.dark-toggle {{ cursor: pointer; font-size: 1.5rem; background: none;
  border: none; padding: 8px; border-radius: 8px; }}
.dark-toggle:hover {{ background: var(--card); }}
.template-selector {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }}
.template-btn {{ padding: 8px 16px; border: 2px solid var(--border); border-radius: 8px;
  background: var(--card); color: var(--fg); cursor: pointer; font-size: 0.9rem;
  transition: all 0.2s; }}
.template-btn:hover {{ border-color: var(--accent); }}
.template-btn.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
.description {{ color: var(--accent); font-size: 0.9rem; margin-bottom: 16px;
  font-style: italic; }}
.section {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px;
  padding: 20px; margin-bottom: 16px; box-shadow: 0 2px 8px var(--shadow); }}
.section h2 {{ font-size: 1.1rem; margin-bottom: 12px; }}
.var-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px; }}
.var-field label {{ display: block; font-size: 0.85rem; font-weight: 600;
  margin-bottom: 4px; color: var(--accent); }}
.var-field input {{ width: 100%; padding: 8px 12px; border: 1px solid var(--border);
  border-radius: 6px; font-size: 0.95rem; background: var(--input-bg);
  color: var(--fg); transition: border 0.2s; }}
.var-field input:focus {{ outline: none; border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(67,97,238,0.15); }}
.template-raw {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.9rem;
  background: var(--code-bg); padding: 16px; border-radius: 8px; white-space: pre-wrap;
  word-break: break-word; line-height: 1.6; }}
.preview {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.9rem;
  background: var(--code-bg); padding: 16px; border-radius: 8px; white-space: pre-wrap;
  word-break: break-word; line-height: 1.6; min-height: 60px; }}
.preview .filled {{ background: var(--highlight); padding: 1px 4px; border-radius: 3px;
  font-weight: 600; }}
.preview .unfilled {{ color: #e74c3c; font-style: italic; }}
.actions {{ display: flex; gap: 8px; margin-top: 12px; }}
.btn {{ padding: 8px 20px; border: none; border-radius: 8px; font-size: 0.9rem;
  cursor: pointer; font-weight: 600; transition: all 0.2s; }}
.btn-primary {{ background: var(--accent); color: #fff; }}
.btn-primary:hover {{ background: var(--accent-hover); }}
.btn-secondary {{ background: var(--card); color: var(--fg); border: 1px solid var(--border); }}
.btn-secondary:hover {{ background: var(--border); }}
.stats {{ display: flex; gap: 16px; font-size: 0.85rem; color: var(--fg); opacity: 0.7;
  margin-top: 8px; }}
.toast {{ position: fixed; bottom: 24px; right: 24px; background: var(--accent);
  color: #fff; padding: 12px 24px; border-radius: 8px; font-size: 0.9rem;
  transform: translateY(80px); opacity: 0; transition: all 0.3s; z-index: 999; }}
.toast.show {{ transform: translateY(0); opacity: 1; }}
.empty {{ text-align: center; padding: 60px; color: var(--fg); opacity: 0.5; font-size: 1.1rem; }}
</style>
</head>
<body>
<div class=""container"">
  <header>
    <h1>🧪 {titleEscaped}</h1>
    {(EnableDarkMode ? @"<button class=""dark-toggle"" onclick=""toggleDark()"" title=""Toggle dark mode"">🌙</button>" : "")}
  </header>
  <div id=""app""></div>
</div>
<div class=""toast"" id=""toast""></div>
<script>
const TEMPLATES = {entriesJson};
let currentIdx = 0;

function escHtml(s) {{ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }}

function getVars(tpl) {{
  const re = /\{{\{{(\w+)\}}\}}/g; const vars = []; let m;
  while ((m = re.exec(tpl)) !== null) {{ if (!vars.includes(m[1])) vars.push(m[1]); }}
  return vars;
}}

function render() {{
  const app = document.getElementById('app');
  if (!TEMPLATES.length) {{ app.innerHTML = '<div class=""empty"">No templates added.</div>'; return; }}
  const t = TEMPLATES[currentIdx];
  const vars = getVars(t.template);

  let html = '<div class=""template-selector"">';
  TEMPLATES.forEach((tt, i) => {{
    html += `<button class=""template-btn ${{i===currentIdx?'active':''}}"" onclick=""selectTemplate(${{i}})"">${{escHtml(tt.name)}}</button>`;
  }});
  html += '</div>';

  if (t.description) html += `<div class=""description"">${{escHtml(t.description)}}</div>`;

  html += '<div class=""section""><h2>📝 Template</h2><div class=""template-raw"">' + escHtml(t.template) + '</div></div>';

  if (vars.length) {{
    html += '<div class=""section""><h2>🔧 Variables</h2><div class=""var-grid"">';
    vars.forEach(v => {{
      const def = t.defaults[v] || '';
      html += `<div class=""var-field""><label>{{{{{{}}}}}${{v}}}}</label><input id=""var-${{v}}"" value=""${{escHtml(def)}}"" placeholder=""Enter ${{v}}..."" oninput=""updatePreview()""></div>`;
    }});
    html += '</div></div>';
  }}

  html += '<div class=""section""><h2>👁️ Live Preview</h2><div class=""preview"" id=""preview""></div>';
  html += '<div class=""stats"" id=""stats""></div>';
  html += '<div class=""actions""><button class=""btn btn-primary"" onclick=""copyRendered()"">📋 Copy Rendered</button>';
  html += '<button class=""btn btn-secondary"" onclick=""resetVars()"">🔄 Reset</button></div></div>';

  app.innerHTML = html;
  updatePreview();
}}

function selectTemplate(i) {{ currentIdx = i; render(); }}

function updatePreview() {{
  const t = TEMPLATES[currentIdx];
  const vars = getVars(t.template);
  const vals = {{}};
  let filled = 0;
  vars.forEach(v => {{
    const el = document.getElementById('var-' + v);
    vals[v] = el ? el.value : '';
    if (vals[v]) filled++;
  }});

  let result = t.template;
  let previewHtml = escHtml(t.template);

  vars.forEach(v => {{
    if (vals[v]) {{
      result = result.replaceAll(`{{{{{{}}}}}${{v}}}}}}`, vals[v]);
      previewHtml = previewHtml.replaceAll(`{{{{{{}}}}}${{v}}}}}}`, `<span class=""filled"">${{escHtml(vals[v])}}</span>`);
    }} else {{
      previewHtml = previewHtml.replaceAll(`{{{{{{}}}}}${{v}}}}}}`, `<span class=""unfilled"">⟨${{v}}⟩</span>`);
    }}
  }});

  document.getElementById('preview').innerHTML = previewHtml;
  const chars = result.length;
  const words = result.split(/\s+/).filter(w => w).length;
  const approxTokens = Math.ceil(chars / 4);
  document.getElementById('stats').innerHTML =
    `<span>📊 ${{chars}} chars</span><span>📝 ${{words}} words</span><span>🪙 ~${{approxTokens}} tokens</span><span>✅ ${{filled}}/${{vars.length}} filled</span>`;
}}

function resetVars() {{
  const t = TEMPLATES[currentIdx];
  getVars(t.template).forEach(v => {{
    const el = document.getElementById('var-' + v);
    if (el) el.value = t.defaults[v] || '';
  }});
  updatePreview();
}}

function copyRendered() {{
  const t = TEMPLATES[currentIdx];
  const vars = getVars(t.template);
  let result = t.template;
  vars.forEach(v => {{
    const el = document.getElementById('var-' + v);
    const val = el ? el.value : '';
    if (val) result = result.replaceAll(`{{{{{{}}}}}${{v}}}}}}`, val);
  }});
  navigator.clipboard.writeText(result).then(() => showToast('Copied to clipboard!')).catch(() => showToast('Copy failed'));
}}

function showToast(msg) {{
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2000);
}}

function toggleDark() {{
  document.documentElement.classList.toggle('dark');
  const btn = document.querySelector('.dark-toggle');
  btn.textContent = document.documentElement.classList.contains('dark') ? '☀️' : '🌙';
}}

render();
</script>
</body>
</html>";
        }

        /// <summary>
        /// Save the generated HTML playground to a file.
        /// </summary>
        public async Task SaveAsync(string filePath, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentException("File path cannot be empty.", nameof(filePath));

            var html = GenerateHtml();
            await File.WriteAllTextAsync(filePath, html, Encoding.UTF8, cancellationToken);
        }

        /// <summary>
        /// Serialize the playground configuration to JSON.
        /// </summary>
        public string ToJson()
        {
            var data = new
            {
                title = Title,
                enableDarkMode = EnableDarkMode,
                entries = _entries
            };
            return JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
        }

        /// <summary>
        /// Load playground configuration from JSON.
        /// </summary>
        public static PromptPlayground FromJson(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
                throw new ArgumentException("JSON cannot be empty.", nameof(json));

            SerializationGuards.CheckPayloadSize(json);

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var playground = new PromptPlayground();

            if (root.TryGetProperty("title", out var titleProp))
                playground.Title = titleProp.GetString() ?? "Prompt Playground";

            if (root.TryGetProperty("enableDarkMode", out var darkProp))
                playground.EnableDarkMode = darkProp.GetBoolean();

            if (root.TryGetProperty("entries", out var entriesProp))
            {
                foreach (var entry in entriesProp.EnumerateArray())
                {
                    var name = entry.GetProperty("name").GetString() ?? "";
                    var template = entry.GetProperty("template").GetString() ?? "";
                    var description = "";
                    if (entry.TryGetProperty("description", out var descProp))
                        description = descProp.GetString() ?? "";

                    var defaults = new Dictionary<string, string>();
                    if (entry.TryGetProperty("defaults", out var defaultsProp))
                    {
                        foreach (var prop in defaultsProp.EnumerateObject())
                        {
                            defaults[prop.Name] = prop.Value.GetString() ?? "";
                        }
                    }

                    playground.AddTemplate(name, template, defaults, description);
                }
            }

            return playground;
        }
    }
}
