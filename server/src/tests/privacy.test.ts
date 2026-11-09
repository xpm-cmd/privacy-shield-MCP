/**
 * privacy.test.ts - Tests for Layer 1 (PII / secret detection and redaction)
 *
 * Secret-shaped fixtures are assembled from parts so that neither the
 * file hook nor repository secret scanners mistake them for real keys.
 */

import { describe, it, expect } from 'vitest';
import { analyzePrivacy } from '../privacy.js';

const fake = (...parts: string[]) => parts.join('');
const names = (text: string) => analyzePrivacy(text).findings.map(f => f.description);

describe('analyzePrivacy - API keys and tokens', () => {
  it('detects modern OpenAI project keys (sk-proj-)', () => {
    expect(names(`OPENAI=${fake('sk-', 'proj-', 'Ab1_'.repeat(12))}`)).toContain('OpenAI API Key');
  });

  it('detects OpenAI service-account keys (sk-svcacct-)', () => {
    expect(names(fake('sk-', 'svcacct-', 'Zz9-'.repeat(10)))).toContain('OpenAI API Key');
  });

  it('detects legacy OpenAI keys', () => {
    expect(names(fake('sk-', 'A1'.repeat(24)))).toContain('OpenAI API Key');
  });

  it('does not treat identifiers that merely contain "sk-" as OpenAI keys', () => {
    expect(names('const id = "task-abcdefghijklmnopqrstuvwxyz"')).not.toContain('OpenAI API Key');
    expect(names('className="sk-loading-placeholder-shimmer-row"')).not.toContain('OpenAI API Key');
  });

  it('reports Anthropic keys as Anthropic, not OpenAI', () => {
    const found = names(fake('sk-', 'ant-', 'api03-', 'x'.repeat(40)));
    expect(found).toContain('Anthropic API Key');
    expect(found).not.toContain('OpenAI API Key');
  });

  it('detects GitHub OAuth, user-to-server and fine-grained tokens', () => {
    expect(names(fake('gho_', 'a'.repeat(36)))).toContain('Token de GitHub');
    expect(names(fake('ghu_', 'b'.repeat(36)))).toContain('Token de GitHub');
    expect(names(fake('github_', 'pat_', 'C'.repeat(60)))).toContain('Token de GitHub');
  });

  it('detects Google, Slack, Hugging Face and Stripe live keys', () => {
    expect(names(fake('AIza', 'B'.repeat(35)))).toContain('Google API Key');
    expect(names(fake('xox', 'b-', '1234567890-abcdef'))).toContain('Token de Slack');
    expect(names(fake('hf_', 'D'.repeat(34)))).toContain('Token de Hugging Face');
    expect(names(fake('sk_', 'live_', 'E'.repeat(24)))).toContain('Stripe live key');
  });

  it('detects encrypted and DSA private key blocks', () => {
    const block = (kind: string) => `-----BEGIN ${kind}PRIVATE KEY-----\nMIIabc\n-----END ${kind}PRIVATE KEY-----`;
    expect(names(block('ENCRYPTED '))).toContain('Clave privada SSH/PEM');
    expect(names(block('DSA '))).toContain('Clave privada SSH/PEM');
  });

  it('detects credentials embedded in a URL and redacts the password', () => {
    const secret = fake('Sup3r', 'S3cret');
    const result = analyzePrivacy(`DATABASE_URL_RO postgres://app:${secret}@db.internal:5432/app`);
    expect(result.findings.map(f => f.description)).toContain('Credenciales en URL');
    expect(result.redacted_text).not.toContain(secret);
  });
});

describe('analyzePrivacy - redaction safety', () => {
  it('never re-inserts the raw match when the redaction contains $-patterns', () => {
    const secret = fake('Sup3r', 'S3cret');
    const result = analyzePrivacy(`postgres://app:${secret}@db.internal/x$&y`);
    expect(result.redacted_text).not.toContain(secret);
  });

  it('redacts every occurrence of a repeated secret', () => {
    const key = fake('AKIA', 'ABCDEFGHIJKLMNOP');
    const result = analyzePrivacy(`a=${key}\nb=${key}`);
    expect(result.redacted_text).not.toContain(key);
  });
});

describe('analyzePrivacy - password heuristics', () => {
  it.each([
    'password: Password',
    'password: string;',
    '    password = _ask_password(user.username)',
    'must_change_password: Mapped[bool] = mapped_column(Boolean)',
    'must_change_password=account.role != "admin",',
    'password: process.env.E2E_PASSWORD,',
    'password=${DB_PASSWORD}',
    'passwordLabel: "Your new password"',
    'passwordLabel="Password"',
    'passwordPlaceholder: "********"',
    `password_hash="${fake('pbkdf2', 'sha256abc')}"`,
    'MIN_PASSWORD_LENGTH = 12',
  ])('ignores code that only names a password field: %s', (line) => {
    expect(names(line)).toEqual([]);
  });

  it.each([
    `password = "${fake('hunter2', 'hunter')}"`,
    `"password": "${fake('C0rrect-', 'Horse')}"`,
    `db_password: ${fake('S3cr3t', '!pass')}`,
  ])('flags a literal password value: %s', (line) => {
    expect(names(line)).toContain('Password en texto plano');
  });

  it('redacts the literal password value', () => {
    const value = fake('hunter2', 'hunter');
    expect(analyzePrivacy(`password = "${value}"`).redacted_text).not.toContain(value);
  });
});

describe('analyzePrivacy - dotenv-style secrets', () => {
  it.each([
    `API_TOKEN=${fake('abc123', 'def456')}`,
    `export GITHUB_TOKEN=${fake('tok', 'en-value-1')}`,
    `DB_PASSWORD=${fake('hunter', '22')}`,
  ])('flags dotenv assignments: %s', (line) => {
    expect(names(line)).toContain('Variable .env con secreto');
  });

  it.each([
    'MIN_KEY_TO_MASK = 8',
    'KEY_BITS = 2048',
    'TOKEN_LIMIT=4096',
    'API_KEY=$OTHER_VAR',
    'API_KEY=',
    'API_KEY=""',
  ])('ignores constants, references and empty values: %s', (line) => {
    expect(names(line)).not.toContain('Variable .env con secreto');
  });
});

describe('analyzePrivacy - financial, phone and location data', () => {
  it('flags Luhn-valid card numbers', () => {
    expect(names('card 4111111111111111')).toContain('Tarjeta de crédito');
  });

  it('ignores 16-digit numbers that fail the Luhn check', () => {
    expect(names('id 4111111111111112')).not.toContain('Tarjeta de crédito');
  });

  it.each(['+56912345678', '+56 9 1234 5678', '+1 415 555 0132', 'tel: +34 612-345-678'])(
    'detects international phone numbers: %s', (phone) => {
      expect(names(phone)).toContain('Teléfono (formato internacional)');
    });

  it('does not read arithmetic as a phone number', () => {
    expect(names('x = 3+12345678')).not.toContain('Teléfono (formato internacional)');
  });

  it('flags plausible coordinates', () => {
    expect(names('location: -33.4489, -70.6693')).toContain('Coordenadas GPS');
  });

  it.each(['[0.1234, 0.5678]', 'pts = [12.3456, 45.6789, 78.9012]', 'v = 123.45678, 200.12345'])(
    'ignores numeric pairs that are not coordinates: %s', (text) => {
      expect(names(text)).not.toContain('Coordenadas GPS');
    });
});
