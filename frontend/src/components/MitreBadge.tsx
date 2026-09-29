import React from 'react';
import { cn } from '@/lib/utils';
import { ShieldAlert } from 'lucide-react';

interface MitreBadgeProps {
  techniqueId: string | null;
  techniqueName: string | null;
  className?: string;
}

export function MitreBadge({ techniqueId, techniqueName, className }: MitreBadgeProps) {
  if (!techniqueId) return null;
  
  return (
    <div className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#1a1f2e] border border-blue-900/50 text-blue-400 text-xs font-medium", className)}>
      <ShieldAlert className="w-3.5 h-3.5" />
      <span>{techniqueId}</span>
      <span className="text-gray-400">—</span>
      <span className="truncate max-w-[200px]">{techniqueName}</span>
    </div>
  );
}
