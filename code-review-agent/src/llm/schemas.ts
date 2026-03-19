import { z } from 'zod';

type JsonSchema = Record<string, unknown>;

export function zodToJsonSchema(schema: z.ZodTypeAny): JsonSchema {
  return convertType(schema);
}

function convertType(schema: z.ZodTypeAny): JsonSchema {
  const def = schema._def;
  const typeName = def.typeName as string;

  switch (typeName) {
    case 'ZodString':
      return { type: 'string' };

    case 'ZodNumber': {
      const result: JsonSchema = { type: 'number' };
      for (const check of def.checks ?? []) {
        if (check.kind === 'min') result.minimum = check.value;
        if (check.kind === 'max') result.maximum = check.value;
      }
      return result;
    }

    case 'ZodBoolean':
      return { type: 'boolean' };

    case 'ZodLiteral':
      return { type: typeof def.value, const: def.value };

    case 'ZodEnum':
      return { type: 'string', enum: def.values };

    case 'ZodArray':
      return { type: 'array', items: convertType(def.type) };

    case 'ZodObject': {
      const shape = def.shape();
      const properties: Record<string, JsonSchema> = {};
      const required: string[] = [];

      for (const [key, value] of Object.entries(shape)) {
        const fieldSchema = value as z.ZodTypeAny;
        const isOptional = fieldSchema.isOptional();
        properties[key] = convertType(fieldSchema);
        if (!isOptional) {
          required.push(key);
        }
      }

      const result: JsonSchema = {
        type: 'object',
        properties,
        additionalProperties: false,
      };
      if (required.length > 0) {
        result.required = required;
      }
      return result;
    }

    case 'ZodOptional':
      return convertType(def.innerType);

    case 'ZodNullable': {
      const inner = convertType(def.innerType);
      return { anyOf: [inner, { type: 'null' }] };
    }

    case 'ZodDefault':
      return convertType(def.innerType);

    case 'ZodEffects':
      return convertType(def.schema);

    case 'ZodUnion': {
      const options = (def.options as z.ZodTypeAny[]).map(convertType);
      return { anyOf: options };
    }

    case 'ZodRecord':
      return {
        type: 'object',
        additionalProperties: convertType(def.valueType),
      };

    default:
      // Fail loud instead of silently producing invalid schema
      throw new Error(`zodToJsonSchema: unsupported Zod type "${typeName}". Add explicit handling for this type.`);
  }
}

export function zodToAnthropicTool(
  schema: z.ZodTypeAny,
  name: string,
  description: string,
): {
  name: string;
  description: string;
  input_schema: JsonSchema;
} {
  return {
    name,
    description,
    input_schema: zodToJsonSchema(schema),
  };
}

export function zodToOpenAIResponseFormat(
  schema: z.ZodTypeAny,
  name: string,
): {
  type: 'json_schema';
  json_schema: { name: string; strict: boolean; schema: JsonSchema };
} {
  return {
    type: 'json_schema',
    json_schema: {
      name,
      strict: true,
      schema: zodToJsonSchema(schema),
    },
  };
}
