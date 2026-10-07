import type { SecurityToolAdapter } from "../adapter/adapter.interface";
import type { Capability, ToolCategory } from "../adapter/adapter.types";
import type { TargetType } from "@dsrclone/types";
import { DuplicateAdapterError } from "../adapter/adapter.errors";
import { validateAdapterMetadata } from "./registry.validation";
import type { RegistryQuery } from "./registry.types";

/** In-memory registry of trusted, code-installed adapters. Adapters are never
 *  uploaded or executed dynamically by users — discovery is a deployment-time
 *  list of built-in adapters (Prompt 3 §20), not a plugin marketplace. */
export class ToolRegistry {
  private readonly bySlug = new Map<string, SecurityToolAdapter>();
  private readonly byId = new Map<string, string>();

  register(adapter: SecurityToolAdapter): void {
    validateAdapterMetadata(adapter.metadata);
    const { slug, id } = adapter.metadata;
    if (this.bySlug.has(slug)) throw new DuplicateAdapterError(`Duplicate adapter slug: ${slug}`);
    if (this.byId.has(id)) throw new DuplicateAdapterError(`Duplicate adapter id: ${id}`);
    this.bySlug.set(slug, adapter);
    this.byId.set(id, slug);
  }

  unregister(slug: string): boolean {
    const a = this.bySlug.get(slug);
    if (!a) return false;
    this.byId.delete(a.metadata.id);
    return this.bySlug.delete(slug);
  }

  resolve(slug: string): SecurityToolAdapter | undefined { return this.bySlug.get(slug); }
  resolveById(id: string): SecurityToolAdapter | undefined {
    const slug = this.byId.get(id);
    return slug ? this.bySlug.get(slug) : undefined;
  }
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
  query(q: RegistryQuery): SecurityToolAdapter[] {
    return this.list().filter((a) => {
      if (q.category && a.metadata.category !== q.category) return false;
      if (q.capability && !a.metadata.capabilities.includes(q.capability)) return false;
      if (q.targetType && !a.metadata.supportedTargetTypes.includes(q.targetType)) return false;
      return true;
    });
  }
  /** Compatibility gate (Prompt 3 §7): an adapter may only run against the
   *  target types it explicitly declares. */
  isCompatible(slug: string, type: TargetType): boolean {
    const a = this.resolve(slug);
    return !!a && a.metadata.supportedTargetTypes.includes(type);
  }
}
