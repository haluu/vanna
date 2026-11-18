/**
 * Helpers for building HTML strings from component data.
 *
 * Component data comes from the server and can contain LLM output, database
 * values, file contents and error messages, any of which an attacker may
 * control (for example through prompt injection). Every value that is placed
 * into an HTML string must go through escapeHtml().
 */

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/** Escape a value for use in HTML text and in quoted attribute values. */
export function escapeHtml(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }
  return String(value).replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch]);
}

/**
 * Render a small subset of Markdown (headings, bold, italics, inline code,
 * lists and paragraphs).
 *
 * The text is escaped before any formatting is applied, so Markdown can only
 * add the tags produced here and cannot inject markup of its own.
 */
export function renderBasicMarkdown(text: unknown): string {
  return escapeHtml(text)
    .replace(/^### (.*$)/gm, '<h3>$1</h3>')
    .replace(/^## (.*$)/gm, '<h2>$1</h2>')
    .replace(/^# (.*$)/gm, '<h1>$1</h1>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^- (.*$)/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/^(?!<[h|u|l|p])(.+)$/gm, '<p>$1</p>');
}
