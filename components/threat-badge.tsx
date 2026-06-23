import { cn } from "@/lib/utils"
import { threatBadgeClass } from "@/lib/format"
import type { ThreatLevel } from "@/lib/types"

export function ThreatBadge({
  level,
  className,
}: {
  level: ThreatLevel
  className?: string
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide",
        threatBadgeClass(level),
        className,
      )}
    >
      {level}
    </span>
  )
}
