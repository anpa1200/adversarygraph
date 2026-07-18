export function PermissionNotice({
  permission,
  action,
  compact = false,
}: {
  permission: string;
  action: string;
  compact?: boolean;
}) {
  return (
    <div
      role="note"
      data-testid={`permission-notice-${permission}`}
      className={compact
        ? 'rounded border border-amber-500/30 bg-amber-950/20 px-3 py-2 text-[11px] leading-5 text-amber-100/80'
        : 'rounded-lg border border-amber-500/30 bg-amber-950/20 p-4 text-xs leading-5 text-amber-100/80'}
    >
      Read-only access. <code className="font-mono text-amber-200">{permission}</code> is required to {action}.
    </div>
  );
}
