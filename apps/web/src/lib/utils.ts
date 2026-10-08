import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** shadcn-standard class merge helper (used by components/ui). */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
