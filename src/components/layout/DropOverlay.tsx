import { Upload } from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';

interface DropOverlayProps {
  visible: boolean;
}

export function DropOverlay({ visible }: DropOverlayProps) {
  const { t } = useLanguage();

  if (!visible) return null;

  return (
    <div
      className="drop-overlay fixed inset-0 z-50 flex items-center justify-center bg-black/25 backdrop-blur-[2px]"
      aria-hidden="false"
    >
      <div className="drop-overlay-card w-full max-w-[420px] p-8 text-center rounded-xl border-2 border-dashed border-white/40 bg-slate-900/95 text-white">
        <Upload className="h-10 w-10 mx-auto mb-3 opacity-80" />
        <h2 className="text-lg font-bold mb-1">{t('drop.title')}</h2>
        <p className="text-sm text-white/80">{t('drop.text')}</p>
      </div>
    </div>
  );
}
