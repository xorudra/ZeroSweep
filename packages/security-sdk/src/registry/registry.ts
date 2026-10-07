import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { Capability, ToolCategory } from "../adapter/adapter.types";
import type { TargetType } from "@dsrclone/types";

/** In-memory registry of trusted, code-installed adapters. Adapters are never
 *  uploaded or executed dynamically by users. */
export class ToolRegistry {
  private readonly bySlug = new Map<string, SecurityToolAdapter>();

  register(adapter: SecurityToolAdapter): void {
    const slug = adapter.metadata.slug;
    if (this.bySlug.has(slug)) throw new Error(`Duplicate adapter slug: ${slug}`);
    this.bySlug.set(slug, adapter);
  }
  unregister(slug: string): boolean { return this.bySlug.delete(slug); }
  resolve(slug: string): SecurityToolAdapter | undefined { return this.bySlug.get(slug); }
  list(): SecurityToolAdapter[] { return [...this.bySlug.values()]; }
  byCategory(category: ToolCategory): SecurityToolAdapter[] {
    return this.list().filter((a) => a.metadata.category === category);
  }
  byCapability(capability: Capability): SecurityToolAdapter[] {
    return this.list().filter((a) => a.metadata.capabilities.includes(capability));
  }
  byTargetType(type: TargetType): SecurityToolAdapter[] {
    return this.list().filter((a) => a.metadata.supportedTargetTypes.includes(type));
  }
}
