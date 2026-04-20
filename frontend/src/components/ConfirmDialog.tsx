interface Props {
  message: string;
  confirmLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({ message, confirmLabel = 'Löschen', onConfirm, onCancel }: Props) {
  return (
    <div
      className="fixed inset-0 bg-black/70 flex items-center justify-center z-[60] p-4"
      onClick={onCancel}
    >
      <div className="card p-5 w-full max-w-sm" onClick={e => e.stopPropagation()}>
        <p className="text-sm text-slate-200 mb-4">{message}</p>
        <div className="flex justify-end gap-2">
          <button onClick={onCancel} className="btn-ghost text-xs">Abbrechen</button>
          <button
            onClick={onConfirm}
            className="px-3 py-1.5 rounded text-xs font-medium bg-red-700 hover:bg-red-600 text-white transition-colors"
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
