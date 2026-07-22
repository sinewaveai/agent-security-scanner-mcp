import { z } from 'zod';

type JsonSchema = Record<string, unknown>;

export function zodToJsonSchema(schema: z.ZodTypeAny, openaiStrict = false): JsonSchema {
  return convertType(schema, openaiStrict);
}

function convertType(schema: z.ZodTypeAny, openaiStrict: boolean): JsonSchema {
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
      return { type: 'array', items: convertType(def.type, openaiStrict) };

    case 'ZodObject': {
      const shape = def.shape();
      const properties: Record<string, JsonSchema> = {};
      const required: string[] = [];

      for (const [key, value] of Object.entries(shape)) {
        const fieldSchema = value as z.ZodTypeAny;
        const isOptional = fieldSchema.isOptional();
        let propSchema = convertType(fieldSchema, openaiStrict);

        // OpenAI's strict structured-output mode requires every property to be
        // listed in `required`; true optionality must instead be expressed by
        // making the field's type nullable. Without this, any schema with an
        // optional field is rejected outright by OpenAI's API (400 Invalid schema),
        // while Anthropic's looser tool-schema rules tolerate the omission.
        if (openaiStrict && isOptional) {
          propSchema = propSchema.anyOf
            ? { anyOf: [...(propSchema.anyOf as JsonSchema[]), { type: 'null' }] }
            : { anyOf: [propSchema, { type: 'null' }] };
        }

        properties[key] = propSchema;
        if (!isOptional || openaiStrict) {
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
      return convertType(def.innerType, openaiStrict);

    case 'ZodNullable': {
      const inner = convertType(def.innerType, openaiStrict);
      return { anyOf: [inner, { type: 'null' }] };
    }

    case 'ZodDefault':
      return convertType(def.innerType, openaiStrict);

    case 'ZodEffects':
      return convertType(def.schema, openaiStrict);

    case 'ZodUnion': {
      const options = (def.options as z.ZodTypeAny[]).map((o) => convertType(o, openaiStrict));
      return { anyOf: options };
    }

    case 'ZodRecord':
      return {
        type: 'object',
        additionalProperties: convertType(def.valueType, openaiStrict),
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
    input_schema: zodToJsonSchema(schema, false),
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
      schema: zodToJsonSchema(schema, true),
    },
  };
}
