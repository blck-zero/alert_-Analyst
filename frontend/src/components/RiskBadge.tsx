import React from 'react';
import { cn } from '@/lib/utils';
import { AlertTriangle, AlertCircle, AlertOctagon, Info } from 'lucide-react';

interface RiskBadgeProps {
  score: number;
  severity: string;
  className?: string;
}

export function RiskBadge({ score, severity, className }: RiskBadgeProps) {
  let colorClass = "bg-gray-500/10 text-gray-500 border-gray-500/20";
  let Icon = Info;
  
  if (severity === 'critical') {
    colorClass = "bg-red-500/10 text-red-500 border-red-500/20";
    Icon = AlertOctagon;
  } else if (severity === 'high') {
    colorClass = "bg-orange-500/10 text-orange-500 border-orange-500/20";
    Icon = AlertTriangle;
  } else if (severity === 'medium') {
    colorClass = "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
    Icon = AlertCircle;
  } else if (severity === 'low') {
    colorClass = "bg-blue-500/10 text-blue-500 border-blue-500/20";
    Icon = Info;
  }

  return (
    <div className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-semibold", colorClass, className)}>
      <Icon className="w-3.5 h-3.5" />
      <span>{score} Risk</span>
      <span className="uppercase text-[10px] opacity-80 tracking-wider">({severity})</span>
    </div>
  );
}
