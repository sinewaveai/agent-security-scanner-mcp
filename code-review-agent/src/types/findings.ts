import { z } from 'zod';

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof SeveritySchema>;

export const CategorySchema = z.enum([
  'logic-bug',
  'security',
  'race-condition',
  'null-ref',
  'boundary',
  'type-error',
  'unhandled-exception',
  'other',
]);
export type Category = z.infer<typeof CategorySchema>;

export const IntentAlignmentSchema = z.enum([
  'violates-intent',
  'matches-intent',
  'unclear',
]);
export type IntentAlignment = z.infer<typeof IntentAlignmentSchema>;

export const RiskDomainSchema = z.enum([
  'web-api',
  'cli-tool',
  'library',
  'build-tool',
  'data-pipeline',
  'desktop-app',
  'unknown',
]);
export type RiskDomain = z.infer<typeof RiskDomainSchema>;

export const LocationSchema = z.object({
  file: z.string(),
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1),
});

export const FindingSchema = z.object({
  title: z.string(),
  severity: SeveritySchema,
  category: CategorySchema,
  location: LocationSchema,
  reasoning: z.string(),
  intentAlignment: IntentAlignmentSchema,
  confidence: z.number().min(0).max(1),
  suggestedAction: z.string(),
  cwe: z.string().optional(),
  owasp: z.string().optional(),
});
export type Finding = z.infer<typeof FindingSchema>;

export const FileAnalysisResponseSchema = z.object({
  findings: z.array(FindingSchema),
});
export type FileAnalysisResponse = z.infer<typeof FileAnalysisResponseSchema>;

export const IntentProfileSchema = z.object({
  purpose: z.string(),
  expectedBehaviors: z.array(z.string()),
  unexpectedBehaviors: z.array(z.string()),
  framework: z.string(),
  riskDomain: RiskDomainSchema,
});
export type IntentProfile = z.infer<typeof IntentProfileSchema>;

export const AreaOfInterestSchema = z.object({
  startLine: z.number(),
  endLine: z.number(),
  reason: z.string(),
});

export const TriageDecisionSchema = z.object({
  action: z.enum(['analyze', 'skip']),
  reason: z.string(),
  areasOfInterest: z.array(AreaOfInterestSchema),
});
export type TriageDecision = z.infer<typeof TriageDecisionSchema>;
