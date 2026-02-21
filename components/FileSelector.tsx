import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  FileImage, 
  FileVideo, 
  FileAudio, 
  FileText, 
  FileSpreadsheet, 
  FileArchive, 
  FileCode, 
  File, 
  X, 
  Plus, 
  FolderOpen, 
  Loader2 
} from 'lucide-react';

interface FileSelectorProps {
  label: string;
  icon: string;
  onFilesSelect: (files: File[]) => void;
  selectedFiles: File[];
  description?: string;
  accentColor?: string;
  allowMultiple?: boolean;
  allowFolder?: boolean;
  accept?: string;
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

const formatBytes = (bytes: number, decimals: number = 2) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

const FileSelector: React.FC<FileSelectorProps> = ({ 
  label, 
  icon, 
  onFilesSelect, 
  selectedFiles, 
  description,
  accentColor = "blue",
  allowMultiple = false,
  allowFolder = false,
  accept,
  translations,
  activeFileIndex,
  activeFileProgress
}) => {
  const inputId = React.useId();
  const folderInputId = React.useId();
  const [previews, setPreviews] = useState<Record<string, string>>({});

  useEffect(() => {
    const newPreviews: Record<string, string> = {};
    const cleanup: (() => void)[] = [];

    selectedFiles.forEach(file => {
      if (file.type.startsWith('image/')) {
        const url = URL.createObjectURL(file);
        newPreviews[file.name + file.size] = url;
        cleanup.push(() => URL.revokeObjectURL(url));
      }
    });

    setPreviews(newPreviews);
    return () => cleanup.forEach(cb => cb());
  }, [selectedFiles]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const filesArray = Array.from(e.target.files);
      if (allowMultiple) {
        onFilesSelect([...selectedFiles, ...filesArray]);
      } else {
        onFilesSelect([filesArray[0]]);
      }
    }
    e.target.value = '';
  };

  const getFileIcon = (file: File) => {
    const type = file.type;
    const name = file.name.toLowerCase();

    if (name.endsWith('.secure')) return <ShieldCheck className="text-sm text-slate-500" />;
    if (type.startsWith('image/')) return <FileImage className="text-sm text-slate-500" />;
    if (type.startsWith('video/')) return <FileVideo className="text-sm text-slate-500" />;
    if (type.startsWith('audio/')) return <FileAudio className="text-sm text-slate-500" />;
    if (type === 'application/pdf') return <FileText className="text-sm text-slate-500" />;
    if (name.endsWith('.doc') || name.endsWith('.docx')) return <FileText className="text-sm text-slate-500" />;
    if (name.endsWith('.xls') || name.endsWith('.xlsx')) return <FileSpreadsheet className="text-sm text-slate-500" />;
    if (name.endsWith('.csv')) return <FileSpreadsheet className="text-sm text-slate-500" />;
    if (name.endsWith('.zip') || name.endsWith('.rar') || name.endsWith('.7z')) return <FileArchive className="text-sm text-slate-500" />;
    if (name.includes('js') || name.includes('ts') || name.includes('html') || name.includes('json')) return <FileCode className="text-sm text-slate-500" />;
    
    return <File className="text-sm text-slate-500" />;
  };

  const getAccentClasses = () => {
    switch(accentColor) {
      case 'emerald': return 'border-emerald-500/30 hover:border-emerald-500 bg-emerald-500/5 text-emerald-400';
      case 'amber': return 'border-amber-500/30 hover:border-amber-500 bg-amber-500/5 text-amber-400';
      default: return 'border-blue-500/30 hover:border-blue-500 bg-blue-500/5 text-blue-400';
    }
  };

  const getProgressBarClasses = () => {
    switch(accentColor) {
      case 'emerald': return 'bg-emerald-500';
      case 'amber': return 'bg-amber-500';
      default: return 'bg-blue-500';
    }
  };

  const removeFile = (index: number) => {
    const newFiles = [...selectedFiles];
    newFiles.splice(index, 1);
    onFilesSelect(newFiles);
  };

  return (
    <div className="flex flex-col space-y-2 w-full animate-in fade-in duration-300">
      <div className="flex justify-between items-center">
        <label className="text-sm font-semibold text-slate-500 uppercase tracking-wider flex items-center gap-2">
          {label}
          {selectedFiles.length > 0 && <span className="text-[10px] bg-white/20 px-1.5 py-0.5 rounded text-white">{selectedFiles.length}</span>}
        </label>
        {selectedFiles.length > 0 && activeFileIndex === undefined && (
          <button 
            onClick={() => onFilesSelect([])}
            className="text-[10px] uppercase font-bold text-red-500 hover:text-red-600 transition-colors"
          >
            {translations.clearAll}
          </button>
        )}
      </div>
      
      <div className={`relative group border-2 border-dashed rounded-xl transition-all duration-300 overflow-hidden min-h-[160px] flex flex-col items-center justify-center ${getAccentClasses()}`}>
        {selectedFiles.length === 0 ? (
          <>
            <div className="absolute inset-0 z-20 flex flex-col items-center justify-center cursor-pointer">
               <input
                type="file"
                id={inputId}
                multiple={allowMultiple}
                accept={accept}
                onChange={handleFileChange}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                aria-label={`${translations.clickOrDrop} ${allowMultiple ? translations.files : translations.file}`}
              />
              <div className="p-6 flex flex-col items-center justify-center text-center w-full">
                <div className="text-3xl mb-3 opacity-60 group-hover:opacity-100 transition-opacity">
                  {label.includes('Key') || label.includes('Clave') ? <ShieldCheck size={32} /> : <File size={32} />}
                </div>
                <p className="text-sm font-bold tracking-tight">{translations.clickOrDrop} {allowMultiple ? translations.files : translations.file}</p>
                {description && <p className="text-[10px] text-slate-500 mt-1 uppercase tracking-widest font-bold opacity-80">{description}</p>}
                
                {allowFolder && (
                   <div className="mt-4 flex gap-2">
                      <label htmlFor={folderInputId} className="px-3 py-1.5 bg-slate-800/80 hover:bg-slate-700 rounded-lg text-[10px] font-bold uppercase transition-all cursor-pointer border border-white/5 shadow-sm flex items-center gap-2">
                        <FolderOpen size={12} />
                        {translations.uploadFolder}
                      </label>
                      <input
                        type="file"
                        id={folderInputId}
                        onChange={handleFileChange}
                        accept={accept}
                        // @ts-ignore
                        webkitdirectory=""
                        directory=""
                        className="hidden"
                        aria-label={translations.uploadFolder}
                      />
                   </div>
                )}
              </div>
            </div>
          </>
        ) : (
          <div className="w-full p-3 max-h-[220px] overflow-y-auto space-y-2 scrollbar-thin" role="list">
            {selectedFiles.map((file, idx) => {
              const preview = previews[file.name + file.size];
              const isProcessing = activeFileIndex === idx;
              
              return (
                <div key={idx} className={`flex flex-col gap-1 bg-slate-900/60 border border-white/5 rounded-lg p-2 group/item shadow-sm transition-all ${isProcessing ? 'ring-2 ring-current ring-offset-2 ring-offset-slate-900' : ''}`} role="listitem">
                  <div className="flex items-center gap-3">
                    {preview ? (
                      <img src={preview} alt="" className="w-8 h-8 rounded object-cover border border-white/10" />
                    ) : (
                      <div className="w-8 h-8 flex items-center justify-center bg-slate-800 rounded">
                        {getFileIcon(file)}
                      </div>
                    )}
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-white truncate font-bold">{file.name}</p>
                      <p className="text-[9px] text-slate-500 font-mono font-bold">{formatBytes(file.size)}</p>
                    </div>
                    {activeFileIndex === undefined && (
                      <button 
                        onClick={() => removeFile(idx)}
                        className="opacity-0 group-hover/item:opacity-100 p-2 text-slate-400 hover:text-red-500 transition-all active:scale-90"
                        aria-label={`${translations.removeFile}: ${file.name}`}
                      >
                        <X size={14} />
                      </button>
                    )}
                    {isProcessing && (
                      <Loader2 size={14} className="animate-spin opacity-60 mr-2" />
                    )}
                  </div>
                  
                  {isProcessing && (
                    <div className="mt-1 flex flex-col gap-1">
                      <div className="h-1 w-full bg-slate-800 rounded-full overflow-hidden shadow-inner">
                        <div 
                          className={`h-full transition-all duration-300 ease-out ${getProgressBarClasses()}`}
                          style={{ width: `${activeFileProgress || 0}%` }}
                        />
                      </div>
                      <div className="flex justify-between items-center text-[8px] font-bold uppercase tracking-tighter opacity-60">
                        <span>{activeFileProgress || 0}% Ready</span>
                        <span>{activeFileProgress === 100 ? 'Finalizing...' : 'Reading...'}</span>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
            
            {allowMultiple && activeFileIndex === undefined && (
              <label className="flex items-center justify-center gap-2 p-3 border border-dashed border-white/10 rounded-lg text-[10px] uppercase font-bold text-blue-500 hover:text-slate-300 hover:border-white/20 transition-all cursor-pointer bg-transparent">
                <Plus size={12} />
                {translations.addMore}
                <input type="file" multiple accept={accept} onChange={handleFileChange} className="hidden" aria-label={translations.addMore} />
              </label>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default FileSelector;