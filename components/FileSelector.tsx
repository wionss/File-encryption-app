
import React, { useRef, useState } from 'react';
import { 
  ShieldCheck, 
  PackageOpen, 
  Fingerprint, 
  Upload, 
  FolderUp, 
  X, 
  File, 
  CheckCircle2,
  AlertCircle
} from 'lucide-react';

interface FileSelectorProps {
  label: string;
  icon: "ShieldCheck" | "PackageOpen" | "Fingerprint";
  onFilesSelect: (files: File[]) => void;
  selectedFiles: File[];
  accept?: string;
  description?: string;
  accentColor?: "blue" | "emerald" | "amber";
  allowMultiple?: boolean;
  allowFolder?: boolean;
  translations: {
    clearAll: string;
    clickOrDrop: string;
    addMore: string;
    uploadFolder: string;
    files: string;
    file: string;
    removeFile: string;
  };
  activeFileIndex?: number;
  activeFileProgress?: number;
}

const FileSelector: React.FC<FileSelectorProps> = ({
  label,
  icon,
  onFilesSelect,
  selectedFiles,
  accept,
  description,
  accentColor = "blue",
  allowMultiple = false,
  allowFolder = false,
  translations,
  activeFileIndex,
  activeFileProgress
}) => {
  const inputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);

  const IconComponent = {
    ShieldCheck,
    PackageOpen,
    Fingerprint
  }[icon];

  const colorClasses = {
    blue: "border-blue-500/30 bg-blue-500/5 text-blue-400 focus-within:border-blue-500/50",
    emerald: "border-emerald-500/30 bg-emerald-500/5 text-emerald-400 focus-within:border-emerald-500/50",
    amber: "border-amber-500/30 bg-amber-500/5 text-amber-400 focus-within:border-amber-500/50"
  }[accentColor];

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const newFiles = Array.from(e.target.files);
      if (allowMultiple) {
        onFilesSelect([...selectedFiles, ...newFiles]);
      } else {
        onFilesSelect([newFiles[0]]);
      }
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files) {
      const newFiles = Array.from(e.dataTransfer.files);
      if (allowMultiple) {
        onFilesSelect([...selectedFiles, ...newFiles]);
      } else {
        onFilesSelect([newFiles[0]]);
      }
    }
  };

  const removeFile = (index: number) => {
    const newFiles = [...selectedFiles];
    newFiles.splice(index, 1);
    onFilesSelect(newFiles);
  };

  const clearAll = () => {
    onFilesSelect([]);
  };

  return (
    <div className="flex flex-col gap-3 w-full">
      <div className="flex justify-between items-end">
        <label className="text-xs font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
          <IconComponent size={14} className={`text-${accentColor}-400`} />
          {label}
        </label>
        {selectedFiles.length > 0 && allowMultiple && (
          <button 
            onClick={clearAll}
            className="text-[10px] font-bold text-slate-500 hover:text-red-400 transition-colors uppercase tracking-tighter"
          >
            {translations.clearAll}
          </button>
        )}
      </div>

      <div 
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-2xl p-6 flex flex-col items-center justify-center gap-3 cursor-pointer transition-all duration-300 ${isDragging ? 'border-white/40 bg-white/5 scale-[0.99]' : colorClasses} ${selectedFiles.length > 0 ? 'py-4' : 'py-10'}`}
      >
        <input 
          ref={inputRef}
          type="file" 
          multiple={allowMultiple}
          accept={accept}
          onChange={handleFileChange}
          className="hidden"
        />
        {allowFolder && (
          <input 
            ref={folderInputRef}
            type="file" 
            webkitdirectory="" 
            directory="" 
            onChange={handleFileChange}
            className="hidden"
          />
        )}

        {selectedFiles.length === 0 ? (
          <>
            <div className={`p-4 rounded-full bg-white/5 border border-white/10 ${isDragging ? 'animate-bounce' : ''}`}>
              <Upload size={24} />
            </div>
            <div className="text-center">
              <p className="text-sm font-bold text-slate-200">{translations.clickOrDrop}</p>
              <p className="text-[10px] text-slate-500 mt-1">{description}</p>
            </div>
          </>
        ) : (
          <div className="w-full space-y-2">
            <div className="flex items-center justify-center gap-2 text-slate-200">
              <CheckCircle2 size={16} className={`text-${accentColor}-400`} />
              <span className="text-xs font-bold">
                {selectedFiles.length} {selectedFiles.length === 1 ? translations.file : translations.files}
              </span>
            </div>
            <div className="flex flex-wrap gap-2 justify-center">
              {allowMultiple && (
                <button 
                  onClick={(e) => { e.stopPropagation(); inputRef.current?.click(); }}
                  className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-[10px] font-bold text-slate-300 hover:bg-white/10 transition-all flex items-center gap-2"
                >
                  <Upload size={12} />
                  {translations.addMore}
                </button>
              )}
              {allowFolder && (
                <button 
                  onClick={(e) => { e.stopPropagation(); folderInputRef.current?.click(); }}
                  className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-[10px] font-bold text-slate-300 hover:bg-white/10 transition-all flex items-center gap-2"
                >
                  <FolderUp size={12} />
                  {translations.uploadFolder}
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {selectedFiles.length > 0 && (
        <div className="max-h-40 overflow-y-auto pr-1 space-y-1 scrollbar-thin">
          {selectedFiles.map((file, idx) => (
            <div 
              key={`${file.name}-${idx}`} 
              className={`group flex items-center justify-between p-2 rounded-xl bg-slate-900/50 border border-white/5 hover:border-white/10 transition-all ${activeFileIndex === idx ? 'ring-1 ring-blue-500/50 bg-blue-500/5' : ''}`}
            >
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <div className={`p-1.5 rounded-lg ${activeFileIndex === idx ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-800 text-slate-500'}`}>
                  <File size={14} />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-[11px] font-medium text-slate-300 truncate">{file.name}</p>
                  <div className="flex items-center gap-2">
                    <p className="text-[9px] text-slate-600">{(file.size / 1024).toFixed(1)} KB</p>
                    {activeFileIndex === idx && activeFileProgress !== undefined && (
                      <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden max-w-[60px]">
                        <div 
                          className="h-full bg-blue-500 transition-all duration-300" 
                          style={{ width: `${activeFileProgress}%` }} 
                        />
                      </div>
                    )}
                  </div>
                </div>
              </div>
              <button 
                onClick={() => removeFile(idx)}
                className="p-1.5 text-slate-600 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100"
                title={translations.removeFile}
              >
                <X size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default FileSelector;
