
import React, { useState, useCallback, useMemo, useEffect, useRef } from 'react';
import { OperationMode } from './types';
import { encryptFile, decryptFile, generateRandomKeyFile, getSaveHandle, writeDataToDestination, FileMetadata, encryptData, decryptData } from './services/cryptoService';
import FileSelector from './components/FileSelector';
import { GoogleGenAI } from "@google/genai";
import { 
  HelpCircle, 
  X, 
  Lock, 
  Unlock, 
  Plus, 
  Search, 
  Trash2, 
  Shield, 
  Sliders, 
  Key, 
  CheckCircle, 
  ShieldCheck, 
  PackageOpen, 
  Fingerprint, 
  Wand2, 
  FileSignature, 
  Dices, 
  Eye, 
  EyeOff, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Save, 
  Loader2, 
  UserCheck,
  MoreVertical,
  Download,
  Upload,
  LogOut,
  Check,
  Circle
} from 'lucide-react';

const MIN_KEY_SIZE_BYTES = 1024;
const VAULT_AUTO_LOCK_TIMEOUT = 5 * 60 * 1000; // 5 minutes
const ALLOWED_ENCRYPTION_EXTENSIONS = ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.jpg', '.jpeg', '.png', '.webp', '.gif', '.csv', '.zip', '.rar'];

type Language = 'en' | 'es';

interface VaultEntry {
  id: string;
  name: string;
  password: string;
  date: number;
}

const TRANSLATIONS = {
  en: {
    title: "SecureFile Crypt v2",
    subtitle: "Zero-knowledge, local-first protection using Physical Key Authenticated Encryption.",
    modeLabel: "What would you like to do?",
    encryptMode: "Lock & Hide",
    encryptSub: "Seal files with a key",
    decryptMode: "Unlock & Verify",
    decryptSub: "Restore original files",
    integrityTitle: "Integrity Verification",
    authenticityConfirmed: "Authenticity Confirmed",
    originalName: "Original Name",
    sealingTime: "Time of Sealing",
    integrityPrompt: "Provide a valid .secure file and its corresponding key to view integrity metadata.",
    step1Encrypt: "Step 1: Files to Secure",
    step1Decrypt: "Step 1: Encrypted Vaults",
    step1DescEncrypt: "Files you want to hide",
    step1DescDecrypt: "Select your .secure files",
    step2Label: "Step 2: Physical Key File",
    step2Desc: "Any unique file you own",
    btnGenerateKey: "Generate Random Key",
    generateKeyTip: "I'll create a unique key for you. Save it safely!",
    passwordLabel: "Master Password",
    passwordPlaceholder: "Enter a password for double security...",
    outputNameLabel: "Final Filename",
    outputNamePlaceholder: "Type the name for your output file...",
    btnGeneratePass: "Generate Secure Pass",
    btnSeal: "Seal My Files Now",
    btnUnlock: "Verify & Unlock Files",
    processing: "Processing",
    of: "of",
    successOp: "Operation Successful!",
    successEnc: "encrypted and sealed",
    successDec: "verified and restored",
    footer: "Private & Local • No Data Leaves Your Device • Authenticated Multi-File Cryptography",
    helpTitle: "System Limits & Help",
    helpClose: "Close",
    helpSections: [
      {
        title: "What can I encrypt?",
        text: `The app currently allows: ${ALLOWED_ENCRYPTION_EXTENSIONS.join(', ')}. These are the most common document and image formats.`
      },
      {
        title: "Are there size limits?",
        text: "Practically, files up to 1GB work perfectly. Files over 2GB may crash your browser due to RAM limitations. Everything happens locally in your device's memory."
      },
      {
        title: "What files CANNOT be encrypted?",
        text: "1. Files locked by the OS. 2. Empty (0-byte) files. 3. Formats outside the allowed list. 4. You cannot use a .secure file as a key."
      },
      {
        title: "Why use a Physical Key?",
        text: "It's like a real-world key. Even if someone knows your password, they can't unlock your files without the exact same file you used as a key."
      },
      {
        title: "Strict Privacy & Offline Mode",
        text: "This app is 100% local. Your files never leave your computer. You can use it without internet. 'Strict Privacy Mode' disables all network calls (AI tips) for maximum security."
      }
    ],
    vault: {
      title: "Password Vault",
      empty: "Your vault is empty.",
      saveToVault: "Save to Vault",
      copy: "Copy",
      copied: "Copied!",
      delete: "Delete",
      clearAll: "Clear All",
      confirmClear: "Are you sure you want to delete all passwords? This action cannot be undone.",
      searchPlaceholder: "Search files...",
      setupTitle: "Set Vault Master Key",
      setupDesc: "This key is required to view your stored passwords.",
      unlockTitle: "Vault Locked",
      unlockDesc: "Enter your Vault Master Key to reveal contents.",
      unlockBtn: "Unlock Vault",
      setupBtn: "Initialize Vault",
      wrongKey: "Incorrect Master Key",
      lockVault: "Lock Vault",
      export: "Export Vault",
      import: "Import Vault",
      importSuccess: "Vault imported successfully!",
      importError: "Invalid vault or wrong key.",
      factoryReset: "Factory Reset",
      factoryResetDesc: "This will permanently delete ALL stored passwords and your Master Key. This action cannot be undone.",
      confirmReset: "I understand, delete everything",
      cancelReset: "Cancel",
      strictPrivacy: "Strict Privacy Mode",
      strictPrivacyDesc: "Disable all network calls (AI tips). Maximum security.",
      privacyStatus: "Security Status"
    },
    ariaLabels: {
      helpButton: "Open help information",
      closeHelp: "Close help information",
      togglePassword: "Toggle password visibility",
      selectEnglish: "Change language to English",
      selectSpanish: "Cambiar idioma a Español",
      removeFile: "Remove file",
      generateKey: "Generate a new random key file",
      generatePass: "Generate a high-security random password",
      vaultButton: "Toggle Password Vault"
    },
    fileSelector: {
      clearAll: "Clear All",
      clickOrDrop: "Click or drop",
      addMore: "Add more",
      uploadFolder: "Upload Folder",
      files: "files",
      file: "file",
      removeFile: "Remove file"
    },
    errors: {
      conflict: "Security Conflict: You've selected the same file as both a target and a key. Please choose a different file.",
      format: "Key Format Issue: An already encrypted '.secure' file cannot be used as a key.",
      empty: "Empty Key File: The file you selected contains no data.",
      sizeRec: "Security Recommendation: This key file is smaller than 1KB. For stronger encryption, we recommend using a larger file like an image or a complex document.",
      missingFiles: "Files Missing: Please select the documents you wish to process first.",
      missingKey: "Key Missing: You must provide a 'Physical File Key' to unlock or lock your files.",
      accessDenied: "Access Denied: The key file or password doesn't match, or the file has been tampered with.",
      invalidVault: "Format Error: One of the selected files is not a valid '.secure' vault.",
      invalidType: "Invalid File Type: Some selected files are not allowed. Please select only supported formats (e.g., .txt, .docx, .jpg, .pdf).",
      invalidFileName: "Invalid Filename: Names cannot contain < > : \" / \\ | ? *",
      missingOutputName: "Output Name Required: Please provide a name for the resulting file.",
      unexpected: "An unexpected error occurred. Please double-check your files."
    },
    passwordStrengths: ["Very Weak", "Weak", "Moderate", "Strong", "Exceptional"],
    passCriteria: {
      length: "Min 8 chars",
      upper: "Uppercase",
      number: "Number",
      special: "Symbol",
      extra: "16+ chars"
    }
  },
  es: {
    title: "SecureFile Crypt v2",
    subtitle: "Protección local de conocimiento cero mediante cifrado autenticado con clave física.",
    modeLabel: "¿Qué deseas hacer?",
    encryptMode: "Bloquear y Ocultar",
    encryptSub: "Sellar archivos con una clave",
    decryptMode: "Desbloquear y Verificar",
    decryptSub: "Restaurar archivos originales",
    integrityTitle: "Verificación de Integridad",
    authenticityConfirmed: "Autenticidad Confirmada",
    originalName: "Nombre Original",
    sealingTime: "Fecha de Sellado",
    integrityPrompt: "Proporciona un archivo .secure válido y su clave correspondiente para ver los metadatos.",
    step1Encrypt: "Paso 1: Archivos a Proteger",
    step1Decrypt: "Paso 1: Bóvedas Cifradas",
    step1DescEncrypt: "Archivos que deseas ocultar",
    step1DescDecrypt: "Selecciona tus archivos .secure",
    step2Label: "Paso 2: Archivo Clave Física",
    step2Desc: "Cualquier archivo único que poseas",
    btnGenerateKey: "Generar Clave Aleatoria",
    generateKeyTip: "Crearé una llave única para ti. ¡Guárdala bien!",
    passwordLabel: "Contraseña Maestra",
    passwordPlaceholder: "Ingresa una contraseña para doble seguridad...",
    outputNameLabel: "Nombre del Archivo Final",
    outputNamePlaceholder: "Escribe el nombre que tendrá el archivo...",
    btnGeneratePass: "Generar Pass Seguro",
    btnSeal: "Sellar mis Archivos Ahora",
    btnUnlock: "Verificar y Desbloquear",
    processing: "Procesando",
    of: "de",
    successOp: "¡Operación Exitosa!",
    successEnc: "cifrados y sellados",
    successDec: "verificados y restaurados",
    footer: "Privado y Local • Los datos no salen de tu dispositivo • Criptografía Multi-Archivo Autenticada",
    helpTitle: "Límites del Sistema y Ayuda",
    helpClose: "Cerrar",
    helpSections: [
      {
        title: "¿Qué puedo cifrar?",
        text: `La app actualmente permite: ${ALLOWED_ENCRYPTION_EXTENSIONS.join(', ')}. Son los formatos más comunes de documentos e imágenes.`
      },
      {
        title: "¿Hay límites de tamaño?",
        text: "Archivos de hasta 1GB funcionan perfecto. Archivos de más de 2GB pueden cerrar tu navegador por falta de RAM. Todo ocurre localmente."
      },
      {
        title: "¿Qué archivos NO se pueden cifrar?",
        text: "1. Archivos bloqueados por el SO. 2. Archivos vacíos (0 bytes). 3. Formatos fuera de la lista permitida. 4. No puedes usar un archivo .secure como llave."
      },
      {
        title: "¿Por qué usar una Llave Física?",
        text: "Es como una llave real. Aunque alguien sepa tu contraseña, no podrá abrir tus archivos sin el archivo exacto que usaste como llave."
      },
      {
        title: "Privacidad Estricta y Modo Offline",
        text: "Esta app es 100% local. Tus archivos nunca salen de tu PC. Puedes usarla sin internet. El 'Modo Privacidad Estricta' desactiva cualquier llamada de red (IA) para máxima seguridad."
      }
    ],
    vault: {
      title: "Bóveda de Claves",
      empty: "Tu bóveda está vacía.",
      saveToVault: "Guardar en Bóveda",
      copy: "Copiar",
      copied: "¡Copiado!",
      delete: "Eliminar",
      clearAll: "Limpiar Todo",
      confirmClear: "¿Estás seguro de que deseas eliminar todas las contraseñas? Esta acción no se puede deshacer.",
      searchPlaceholder: "Buscar archivos...",
      setupTitle: "Definir Clave Maestra de Bóveda",
      setupDesc: "Esta clave especial será necesaria para ver las contraseñas guardadas.",
      unlockTitle: "Bóveda Bloqueada",
      unlockDesc: "Ingresa tu Clave Maestra para ver el contenido.",
      unlockBtn: "Desbloquear Bóveda",
      setupBtn: "Inicializar Bóveda",
      wrongKey: "Clave Maestra Incorrecta",
      lockVault: "Bloquear Bóveda",
      export: "Exportar Bóveda",
      import: "Importar Bóveda",
      importSuccess: "¡Bóveda importada con éxito!",
      importError: "Bóveda inválida o clave incorrecta.",
      factoryReset: "Restablecimiento de Fábrica",
      factoryResetDesc: "Esto eliminará permanentemente TODAS las contraseñas guardadas y tu Clave Maestra. Esta acción no se puede deshacer.",
      confirmReset: "Entiendo, borrar todo",
      cancelReset: "Cancelar",
      strictPrivacy: "Modo Privacidad Estricta",
      strictPrivacyDesc: "Desactiva todas las llamadas de red (IA). Máxima seguridad.",
      privacyStatus: "Estado de Seguridad"
    },
    ariaLabels: {
      helpButton: "Abrir ayuda",
      closeHelp: "Cerrar ayuda",
      togglePassword: "Alternar visibilidad de contraseña",
      selectEnglish: "Change language to English",
      selectSpanish: "Cambiar idioma a Español",
      removeFile: "Eliminar archivo",
      generateKey: "Generar un nuevo archivo de clave aleatoria",
      generatePass: "Generar una contraseña aleatoria de alta seguridad",
      vaultButton: "Alternar Bóveda de Contraseñas"
    },
    fileSelector: {
      clearAll: "Limpiar Todo",
      clickOrDrop: "Haz clic o arrastra",
      addMore: "Agregar más",
      uploadFolder: "Subir Carpeta",
      files: "archivos",
      file: "archivo",
      removeFile: "Eliminar archivo"
    },
    errors: {
      conflict: "Conflicto de Seguridad: Has seleccionado el mismo archivo como objetivo y clave. Elige uno diferente.",
      format: "Problema de Formato: Un archivo '.secure' ya cifrado no puede usarse como clave.",
      empty: "Archivo de Clave Vacío: El archivo seleccionado no contiene datos.",
      sizeRec: "Recomendación de Seguridad: Este archivo clave es menor a 1KB. Para un cifrado más fuerte, recomendamos usar un archivo más grande como una imagen o un documento complejo.",
      missingFiles: "Faltan Archivos: Selecciona los documentos que deseas procesar primero.",
      missingKey: "Falta la Clave: Debes proporcionar una 'Clave Física' para bloquear o desbloquear.",
      accessDenied: "Acceso Denegado: La clave o contraseña no coinciden, o el archivo ha sido alterado.",
      invalidVault: "Error de Formato: Uno de los archivos no es una bóveda '.secure' válida.",
      invalidType: "Tipo de Archivo No Permitido: Algunos archivos seleccionados no son compatibles. Usa formatos como .txt, .docx, .jpg, .pdf.",
      invalidFileName: "Nombre Inválido: Los nombres no pueden contener < > : \" / \\ | ? *",
      missingOutputName: "Nombre Requerido: Por favor, indica un nombre para el archivo resultante.",
      unexpected: "Ocurrió un error inesperado. Por favor, revisa tus archivos."
    },
    passwordStrengths: ["Muy Débil", "Débil", "Moderada", "Fuerte", "Excepcional"],
    passCriteria: {
      length: "8+ caracteres",
      upper: "Mayúsculas",
      number: "Números",
      special: "Símbolos",
      extra: "16+ caracteres"
    }
  }
};

const App: React.FC = () => {
  const [lang, setLang] = useState<Language>(() => (localStorage.getItem('lang') as Language) || 'es');
  const [isHelpOpen, setIsHelpOpen] = useState(false);
  const [isVaultOpen, setIsVaultOpen] = useState(false);
  const [isVaultMenuOpen, setIsVaultMenuOpen] = useState(false);
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);
  const [strictPrivacy, setStrictPrivacy] = useState<boolean>(() => localStorage.getItem('strict_privacy') === 'true');
  const [vaultSearch, setVaultSearch] = useState("");
  const [vault, setVault] = useState<VaultEntry[]>([]);
  
  // Vault Security States
  const [vaultMasterKey, setVaultMasterKey] = useState<string>(() => localStorage.getItem('vault_master_key') || "");
  const [isVaultUnlocked, setIsVaultUnlocked] = useState(false);
  const [vaultKeyInput, setVaultKeyInput] = useState("");
  const [vaultError, setVaultError] = useState(false);

  const vaultRef = useRef<HTMLDivElement>(null);
  const t = TRANSLATIONS[lang];

  // Load vault from encrypted storage
  useEffect(() => {
    const loadVault = async () => {
      const encrypted = localStorage.getItem('secure_vault_v2');
      if (!encrypted || !vaultMasterKey || !isVaultUnlocked) {
        if (!encrypted) setVault([]);
        return;
      }
      try {
        const binary = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
        const decrypted = await decryptData(binary, vaultMasterKey);
        const json = new TextDecoder().decode(decrypted);
        setVault(JSON.parse(json));
      } catch (e) {
        console.error("Failed to decrypt vault", e);
        setVault([]);
      }
    };
    loadVault();
  }, [vaultMasterKey, isVaultUnlocked]);

  // Save vault to encrypted storage
  const saveVaultEncrypted = useCallback(async (newVault: VaultEntry[]) => {
    if (!vaultMasterKey) return;
    try {
      const json = JSON.stringify(newVault);
      const binary = new TextEncoder().encode(json);
      const encrypted = await encryptData(binary, vaultMasterKey);
      const base64 = btoa(String.fromCharCode(...encrypted));
      localStorage.setItem('secure_vault_v2', base64);
    } catch (e) {
      console.error("Failed to save vault", e);
    }
  }, [vaultMasterKey]);

  useEffect(() => {
    if (isVaultUnlocked && vault.length > 0) {
      saveVaultEncrypted(vault);
    }
  }, [vault, isVaultUnlocked, saveVaultEncrypted]);

  // Auto-lock logic
  useEffect(() => {
    let timeoutId: NodeJS.Timeout;

    const resetTimer = () => {
      if (timeoutId) clearTimeout(timeoutId);
      if (isVaultUnlocked) {
        timeoutId = setTimeout(() => {
          setIsVaultUnlocked(false);
          setIsVaultMenuOpen(false);
        }, VAULT_AUTO_LOCK_TIMEOUT);
      }
    };

    if (isVaultUnlocked) {
      resetTimer();
      const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
      events.forEach(event => document.addEventListener(event, resetTimer));

      return () => {
        if (timeoutId) clearTimeout(timeoutId);
        events.forEach(event => document.removeEventListener(event, resetTimer));
      };
    }
  }, [isVaultUnlocked]);

  const [targetFiles, setTargetFiles] = useState<File[]>([]);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [password, setPassword] = useState<string>("");
  const [customOutputName, setCustomOutputName] = useState<string>("");
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [mode, setMode] = useState<OperationMode>(OperationMode.ENCRYPT);
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState({ current: 0, total: 0, percent: 0 });
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [legitimacyMeta, setLegitimacyMeta] = useState<FileMetadata | null>(null);
  const [securityTip, setSecurityTip] = useState<string>("");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    localStorage.setItem('lang', lang);
  }, [lang]);

  useEffect(() => {
    localStorage.setItem('strict_privacy', String(strictPrivacy));
  }, [strictPrivacy]);

  // Click outside vault handler
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (vaultRef.current && !vaultRef.current.contains(event.target as Node)) {
        setIsVaultOpen(false);
        // Reset unlock state when closing to maintain security? 
        // Optional: setIsVaultUnlocked(false);
      }
    };
    if (isVaultOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isVaultOpen]);

  // Set default suggested name
  useEffect(() => {
    if (targetFiles.length === 1) {
      const file = targetFiles[0];
      if (mode === OperationMode.ENCRYPT) {
        setCustomOutputName(`${file.name}.secure`);
      } else {
        setCustomOutputName(file.name.endsWith('.secure') ? file.name.slice(0, -7) : `restored_${file.name}`);
      }
    } else {
      setCustomOutputName("");
    }
  }, [targetFiles, mode]);

  const passwordStrength = useMemo(() => {
    const checks = {
      length: password.length >= 8,
      upper: /[A-Z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[^A-Za-z0-9]/.test(password),
      extra: password.length >= 16
    };
    if (!password) return { score: 0, label: "", color: "bg-slate-800", checks };
    let score = 0;
    if (checks.length) score++;
    if (checks.upper) score++;
    if (checks.number) score++;
    if (checks.special) score++;
    if (checks.extra) score++;
    const colors = ["bg-red-500", "bg-red-400", "bg-amber-500", "bg-blue-500", "bg-emerald-500"];
    const idx = Math.max(0, Math.min(score - 1, 4));
    return { label: t.passwordStrengths[idx], color: colors[idx], score, checks };
  }, [password, t]);

  const targetAccept = useMemo(() => {
    if (mode === OperationMode.ENCRYPT) return ALLOWED_ENCRYPTION_EXTENSIONS.join(',');
    return '.secure';
  }, [mode]);

  const handleGenerateKey = useCallback(() => {
    const file = generateRandomKeyFile();
    setKeyFile(file);
    const url = URL.createObjectURL(file);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, []);

  const handleGeneratePassword = useCallback(() => {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
    let retVal = "";
    const length = 20;
    const values = new Uint32Array(length);
    window.crypto.getRandomValues(values);
    for (let i = 0; i < length; i++) {
      retVal += charset.charAt(values[i] % charset.length);
    }
    setPassword(retVal);
    setShowPassword(true);
  }, []);

  useEffect(() => {
    let currentError: string | null = null;
    if (targetFiles.length > 0) {
      if (mode === OperationMode.ENCRYPT) {
        const hasInvalid = targetFiles.some(f => {
          const ext = '.' + f.name.split('.').pop()?.toLowerCase();
          return !ALLOWED_ENCRYPTION_EXTENSIONS.includes(ext);
        });
        if (hasInvalid) currentError = t.errors.invalidType;
      } else {
        const hasInvalid = targetFiles.some(f => !f.name.toLowerCase().endsWith('.secure'));
        if (hasInvalid) currentError = t.errors.invalidVault;
      }
    }
    if (targetFiles.length > 0 && keyFile && !currentError) {
      const isIdentical = targetFiles.some(f => 
        f.name === keyFile.name && f.size === keyFile.size && f.lastModified === keyFile.lastModified
      );
      if (isIdentical) currentError = t.errors.conflict;
    }
    if (customOutputName && /[<>:"/\\|?*]/.test(customOutputName)) {
      currentError = t.errors.invalidFileName;
    }
    if (targetFiles.length === 1 && !customOutputName.trim()) {
      currentError = t.errors.missingOutputName;
    }
    if (keyFile && !currentError) {
      if (keyFile.name.endsWith('.secure')) currentError = t.errors.format;
      else if (keyFile.size === 0) currentError = t.errors.empty;
      else if (keyFile.size < MIN_KEY_SIZE_BYTES) currentError = t.errors.sizeRec;
    }
    setError(currentError);
  }, [targetFiles, keyFile, mode, t, customOutputName]);

  const handleProcess = async () => {
    if (targetFiles.length === 0) {
      setError(t.errors.missingFiles);
      return;
    }
    if (!keyFile) {
      setError(t.errors.missingKey);
      return;
    }
    if (error && error !== t.errors.sizeRec) return;

    setIsLoading(true);
    setError(null);
    setSuccess(null);
    setLegitimacyMeta(null);
    setProgress({ current: 0, total: targetFiles.length, percent: 0 });

    try {
      const isBatch = targetFiles.length > 1;
      let singleFileHandle: any = null;
      if (!isBatch) {
        const suggestedName = customOutputName.trim() || (mode === OperationMode.ENCRYPT 
          ? `${targetFiles[0].name}.secure` 
          : (targetFiles[0].name.endsWith('.secure') ? targetFiles[0].name.slice(0, -7) : `decrypted_${targetFiles[0].name}`));
        try {
          singleFileHandle = await getSaveHandle(suggestedName, 'application/octet-stream');
        } catch (abortErr) {
          setIsLoading(false);
          return;
        }
      }

      for (let i = 0; i < targetFiles.length; i++) {
        const file = targetFiles[i];
        setProgress(prev => ({ ...prev, current: i + 1, percent: 0 }));
        const updateFilePercent = (p: number) => setProgress(prev => ({ ...prev, percent: p }));

        if (mode === OperationMode.ENCRYPT) {
          const encryptedData = await encryptFile(file, keyFile, password, updateFilePercent);
          const fileName = isBatch ? `${file.name}.secure` : (customOutputName || `${file.name}.secure`);
          await writeDataToDestination(encryptedData, isBatch ? null : singleFileHandle, fileName, 'application/octet-stream');
        } else {
          const result = await decryptFile(file, keyFile, password, updateFilePercent);
          const defaultName = file.name.endsWith('.secure') ? file.name.slice(0, -7) : `decrypted_${file.name}`;
          const fileName = isBatch ? defaultName : (customOutputName || defaultName);
          await writeDataToDestination(result.data, isBatch ? null : singleFileHandle, fileName, 'application/octet-stream');
          setLegitimacyMeta(result.meta);
        }
      }
      const actionLabel = mode === OperationMode.ENCRYPT ? t.successEnc : t.successDec;
      setSuccess(`${t.successOp} ${targetFiles.length} ${t.fileSelector.files} ${actionLabel}.`);
    } catch (err: any) {
      if (err.message.includes("Integrity Failure")) setError(t.errors.accessDenied);
      else if (err.message.includes("Invalid Source")) setError(t.errors.invalidVault);
      else setError(t.errors.unexpected);
    } finally {
      setIsLoading(false);
      setProgress({ current: 0, total: 0, percent: 0 });
    }
  };

  const handleSaveToVault = () => {
    if (mode === OperationMode.ENCRYPT && password) {
      const newEntries = targetFiles.map(f => ({
        id: crypto.randomUUID(),
        name: targetFiles.length === 1 && customOutputName ? customOutputName : `${f.name}.secure`,
        password,
        date: Date.now()
      }));
      setVault(prev => [...prev, ...newEntries]);
      setSuccess(prev => prev ? `${prev} (${t.vault.saveToVault})` : t.vault.saveToVault);
    }
  };

  const deleteVaultEntry = (id: string) => {
    setVault(prev => prev.filter(e => e.id !== id));
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredVault = useMemo(() => {
    if (!vaultSearch) return vault;
    return vault.filter(e => e.name.toLowerCase().includes(vaultSearch.toLowerCase()));
  }, [vault, vaultSearch]);

  const handleVaultAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vaultMasterKey) {
      if (vaultKeyInput.length >= 4) {
        localStorage.setItem('vault_master_key', vaultKeyInput);
        setVaultMasterKey(vaultKeyInput);
        setIsVaultUnlocked(true);
        setVaultKeyInput("");
        // Initialize empty vault
        await saveVaultEncrypted([]);
      }
    } else {
      if (vaultKeyInput === vaultMasterKey) {
        setIsVaultUnlocked(true);
        setVaultError(false);
        setVaultKeyInput("");
      } else {
        setVaultError(true);
      }
    }
  };

  const handleExportVault = async () => {
    if (!isVaultUnlocked || !vaultMasterKey) return;
    
    try {
      // Re-encrypt on the fly to ensure we have the latest data and it's valid
      const json = JSON.stringify(vault);
      const binary = new TextEncoder().encode(json);
      const encrypted = await encryptData(binary, vaultMasterKey);
      
      const blob = new Blob([encrypted], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `secure_vault_${new Date().toISOString().split('T')[0]}.vault`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setIsVaultMenuOpen(false);
    } catch (e) {
      console.error("Export failed", e);
      setError(t.vault.unexpected || "Export failed");
    }
  };

  const handleImportVault = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.vault';
    input.onchange = async (e: any) => {
      const file = e.target.files[0];
      if (!file) return;
      
      // We need a password to decrypt the imported file
      const importPass = window.prompt(lang === 'en' ? "Enter the Master Password for this vault file:" : "Ingresa la Clave Maestra para este archivo de bóveda:");
      if (!importPass) return;

      try {
        const buffer = await file.arrayBuffer();
        const binary = new Uint8Array(buffer);
        
        // Try to decrypt with the provided password
        const decrypted = await decryptData(binary, importPass);
        const json = new TextDecoder().decode(decrypted);
        const importedVault = JSON.parse(json);
        
        // If successful, we update the app's master key and vault
        localStorage.setItem('vault_master_key', importPass);
        setVaultMasterKey(importPass);
        setVault(importedVault);
        setIsVaultUnlocked(true);
        
        // Save the encrypted version to local storage
        const encryptedBase64 = btoa(String.fromCharCode(...binary));
        localStorage.setItem('secure_vault_v2', encryptedBase64);
        
        setSuccess(t.vault.importSuccess);
      } catch (err) {
        setError(t.vault.importError);
      }
      setIsVaultMenuOpen(false);
    };
    input.click();
  };

  const handleFactoryReset = () => {
    setVault([]);
    localStorage.removeItem('vault_master_key');
    localStorage.removeItem('secure_vault_v2');
    localStorage.removeItem('secure_vault'); // Legacy
    setVaultMasterKey("");
    setIsVaultUnlocked(false);
    setIsVaultMenuOpen(false);
    setIsResetModalOpen(false);
    setSuccess(lang === 'en' ? "Application reset successfully." : "Aplicación restablecida con éxito.");
  };

  const getSecurityInsight = useCallback(async () => {
    if (!keyFile) return;
    try {
      // Local fallbacks in case of no internet or API failure
      const localTips = lang === 'en' 
        ? [
            "A physical key file acts as a 'something you have' factor, making your encryption significantly harder to breach.",
            "Using a large image or document as a key file increases entropy and security.",
            "Remember: without this specific key file, your encrypted data cannot be recovered even with the password.",
            "Combining a file key with a master password creates a true multi-factor encryption layer."
          ]
        : [
            "Un archivo clave físico actúa como un factor de 'algo que tienes', haciendo que tu cifrado sea mucho más difícil de vulnerar.",
            "Usar una imagen grande o un documento complejo como archivo clave aumenta la entropía y la seguridad.",
            "Recuerda: sin este archivo clave específico, tus datos cifrados no podrán recuperarse ni siquiera con la contraseña.",
            "Combinar una clave de archivo con una contraseña maestra crea una verdadera capa de cifrado de doble factor."
          ];
      
      const randomLocalTip = localTips[Math.floor(Math.random() * localTips.length)];
      setSecurityTip(randomLocalTip);

      // Try to get a fresh AI tip if online AND NOT in strict privacy mode
      if (typeof navigator !== 'undefined' && navigator.onLine && !strictPrivacy) {
        const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
        const prompt = lang === 'en' 
          ? "Explain in one short, helpful sentence why combining a physical file key with a master password provides 'multi-factor' security for local file storage."
          : "Explica en una frase corta y útil por qué combinar un archivo clave físico con una contraseña maestra proporciona seguridad de 'doble factor' para el almacenamiento local.";
        
        const response = await ai.models.generateContent({
          model: 'gemini-3-flash-preview',
          contents: prompt,
          config: {
            systemInstruction: lang === 'en' ? "Friendly cybersecurity mentor." : "Mentor amigable de ciberseguridad."
          }
        });
        if (response.text) setSecurityTip(response.text);
      }
    } catch (e) {
      // Fallback already set above
    }
  }, [keyFile, lang]);

  useEffect(() => {
    if (keyFile) getSecurityInsight();
    else setSecurityTip("");
  }, [keyFile, getSecurityInsight]);

  const isButtonDisabled = useMemo(() => {
    if (targetFiles.length === 0 || !keyFile || isLoading) return true;
    if (error && (error !== t.errors.sizeRec)) return true;
    return false;
  }, [targetFiles, keyFile, isLoading, error]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 flex flex-col items-center p-4 md:p-8 relative font-sans">
      
      {/* Help Modal */}
      {isHelpOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-300">
          <div className="bg-slate-900 border border-white/10 w-full max-w-xl rounded-3xl overflow-hidden shadow-2xl">
            <div className="p-6 md:p-8">
              <div className="flex justify-between items-center mb-6">
                <h3 className="text-xl font-bold text-white flex items-center gap-3">
                  <HelpCircle className="text-blue-400" />
                  {t.helpTitle}
                </h3>
                <button onClick={() => setIsHelpOpen(false)} className="text-slate-400 hover:text-white transition-colors">
                  <X size={24} />
                </button>
              </div>
              <div className="space-y-6 max-h-[60vh] overflow-y-auto pr-2 scrollbar-thin">
                {t.helpSections.map((section, idx) => (
                  <div key={idx} className="bg-slate-800/50 p-4 rounded-2xl border border-white/5">
                    <h4 className="font-bold text-sm text-blue-300 mb-2 uppercase tracking-wide">{section.title}</h4>
                    <p className="text-sm text-slate-300 leading-relaxed">{section.text}</p>
                  </div>
                ))}
              </div>
              <button onClick={() => setIsHelpOpen(false)} className="w-full mt-8 py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl transition-all shadow-lg shadow-blue-600/20">
                {t.helpClose}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Factory Reset Modal */}
      {isResetModalOpen && (
        <div className="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-slate-950/90 backdrop-blur-md animate-in fade-in duration-300">
          <div className="bg-slate-900 border border-red-500/30 rounded-3xl max-w-md w-full p-8 shadow-2xl shadow-red-500/10 animate-in zoom-in-95 duration-300">
            <div className="flex flex-col items-center text-center">
              <div className="w-20 h-20 bg-red-500/10 rounded-full flex items-center justify-center text-red-500 mb-6 border border-red-500/20">
                <ShieldAlert size={40} />
              </div>
              <h3 className="text-2xl font-bold text-white mb-4">{t.vault.factoryReset}</h3>
              <p className="text-slate-400 text-sm leading-relaxed mb-8">
                {t.vault.factoryResetDesc}
              </p>
              <div className="flex flex-col w-full gap-3">
                <button 
                  onClick={handleFactoryReset}
                  className="w-full py-4 bg-red-600 hover:bg-red-500 text-white rounded-2xl font-bold transition-all shadow-lg shadow-red-600/20 active:scale-95 flex items-center justify-center gap-2"
                >
                  <Trash2 size={18} />
                  {t.vault.confirmReset}
                </button>
                <button 
                  onClick={() => setIsResetModalOpen(false)}
                  className="w-full py-4 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-2xl font-bold transition-all"
                >
                  {t.vault.cancelReset}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Top Left Controls */}
      <div className="fixed top-4 left-4 md:top-6 md:left-6 flex items-center gap-2 md:gap-3 z-50">
        <div className="relative" ref={vaultRef}>
          <button 
            onClick={() => setIsVaultOpen(!isVaultOpen)}
            className={`w-10 h-10 flex items-center justify-center rounded-full border border-white/10 transition-all shadow-lg ${isVaultOpen ? 'bg-blue-600 text-white' : 'bg-slate-800/60 text-slate-400 hover:text-white backdrop-blur-md'}`}
            aria-label={t.ariaLabels.vaultButton}
          >
            <Lock size={18} />
          </button>
          
          {isVaultOpen && (
            <div className="absolute left-0 mt-3 w-80 bg-slate-900 border border-white/10 rounded-2xl shadow-2xl overflow-hidden animate-in fade-in slide-in-from-top-2 duration-200">
              <div className="p-4 border-b border-white/5 bg-slate-800/50 flex justify-between items-center">
                <h4 className="text-xs font-bold uppercase tracking-widest text-blue-400">{t.vault.title}</h4>
                <div className="flex gap-2 relative">
                  <button 
                    onClick={() => setIsVaultMenuOpen(!isVaultMenuOpen)}
                    className="text-slate-400 hover:text-white transition-colors p-1"
                  >
                    <MoreVertical size={14} />
                  </button>
                  
                  {isVaultMenuOpen && (
                    <div className="absolute right-0 top-full mt-2 w-48 bg-slate-800 border border-white/10 rounded-xl shadow-2xl z-[60] overflow-hidden animate-in fade-in zoom-in-95 duration-150">
                      <div className="p-1">
                        {isVaultUnlocked && (
                          <button 
                            onClick={handleExportVault}
                            className="w-full flex items-center gap-3 px-3 py-2 text-[11px] font-bold text-slate-300 hover:text-white hover:bg-white/5 rounded-lg transition-all"
                          >
                            <Download size={14} className="text-blue-400" />
                            {t.vault.export}
                          </button>
                        )}
                        <button 
                          onClick={handleImportVault}
                          className="w-full flex items-center gap-3 px-3 py-2 text-[11px] font-bold text-slate-300 hover:text-white hover:bg-white/5 rounded-lg transition-all"
                        >
                          <Upload size={14} className="text-emerald-400" />
                          {t.vault.import}
                        </button>
                        {isVaultUnlocked && (
                          <button 
                            onClick={() => {setIsVaultUnlocked(false); setIsVaultMenuOpen(false);}}
                            className="w-full flex items-center gap-3 px-3 py-2 text-[11px] font-bold text-slate-300 hover:text-white hover:bg-white/5 rounded-lg transition-all"
                          >
                            <LogOut size={14} className="text-amber-400" />
                            {t.vault.lockVault}
                          </button>
                        )}
                        <button 
                          onClick={() => setStrictPrivacy(!strictPrivacy)}
                          className="w-full flex items-center justify-between px-3 py-2 text-[11px] font-bold text-slate-300 hover:text-white hover:bg-white/5 rounded-lg transition-all"
                        >
                          <div className="flex items-center gap-3">
                            <Shield size={14} className={strictPrivacy ? "text-emerald-400" : "text-slate-500"} />
                            {t.vault.strictPrivacy}
                          </div>
                          <div className={`w-6 h-3 rounded-full relative transition-colors ${strictPrivacy ? 'bg-emerald-500' : 'bg-slate-700'}`}>
                            <div className={`absolute top-0.5 w-2 h-2 bg-white rounded-full transition-all ${strictPrivacy ? 'left-3.5' : 'left-0.5'}`} />
                          </div>
                        </button>
                        <button 
                          onClick={() => setIsResetModalOpen(true)} 
                          className="w-full flex items-center gap-3 px-3 py-2 text-[11px] font-bold text-red-400 hover:text-red-300 hover:bg-red-500/5 rounded-lg transition-all"
                        >
                          <Trash2 size={14} />
                          {t.vault.factoryReset}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
              
              {!isVaultUnlocked ? (
                <div className="p-6 flex flex-col items-center gap-4 text-center animate-in fade-in zoom-in-95 duration-200">
                  <div className="w-12 h-12 bg-slate-800 rounded-full flex items-center justify-center text-blue-400 mb-2">
                    {!vaultMasterKey ? <Plus size={20} /> : <Unlock size={20} />}
                  </div>
                  <div className="space-y-1">
                    <h5 className="text-sm font-bold text-white">{!vaultMasterKey ? t.vault.setupTitle : t.vault.unlockTitle}</h5>
                    <p className="text-[10px] text-slate-500">{!vaultMasterKey ? t.vault.setupDesc : t.vault.unlockDesc}</p>
                  </div>
                  <form onSubmit={handleVaultAuth} className="w-full space-y-3">
                    <input 
                      type="password"
                      autoFocus
                      value={vaultKeyInput}
                      onChange={(e) => {setVaultKeyInput(e.target.value); setVaultError(false);}}
                      placeholder="••••••••"
                      className={`w-full bg-slate-800 border-2 rounded-xl py-2 px-3 text-center font-mono text-sm outline-none transition-all ${vaultError ? 'border-red-500/50 shake' : 'border-white/5 focus:border-blue-500/50'}`}
                    />
                    {vaultError && <p className="text-[10px] text-red-500 font-bold uppercase animate-in fade-in">{t.vault.wrongKey}</p>}
                    <button type="submit" className="w-full bg-blue-600 hover:bg-blue-500 py-2 rounded-xl text-xs font-bold transition-all shadow-lg shadow-blue-600/20 active:scale-95">
                      {!vaultMasterKey ? t.vault.setupBtn : t.vault.unlockBtn}
                    </button>
                  </form>
                </div>
              ) : (
                <div className="p-2 animate-in fade-in duration-300">
                  <div className="relative mb-2">
                    <input 
                      type="text" 
                      value={vaultSearch}
                      onChange={(e) => setVaultSearch(e.target.value)}
                      placeholder={t.vault.searchPlaceholder}
                      className="w-full bg-slate-800 border-none rounded-lg py-1.5 px-3 text-[11px] placeholder:text-slate-600 focus:ring-1 focus:ring-blue-500/50 outline-none"
                    />
                    <Search className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-600" size={10} />
                  </div>
                  
                  <div className="max-h-80 overflow-y-auto scrollbar-thin px-1">
                    {filteredVault.length === 0 ? (
                      <p className="text-center py-8 text-slate-600 text-[10px] italic">{t.vault.empty}</p>
                    ) : (
                      <div className="space-y-1 pb-2">
                        {filteredVault.map(entry => (
                          <div key={entry.id} className="group p-2 rounded-xl bg-white/5 hover:bg-white/10 border border-transparent hover:border-white/5 transition-all">
                            <div className="flex justify-between items-start gap-2">
                              <div className="min-w-0 flex-1">
                                <p className="text-[11px] font-bold text-slate-200 truncate">{entry.name}</p>
                                <p className="text-[9px] text-slate-500">{new Date(entry.date).toLocaleDateString()}</p>
                              </div>
                              <button onClick={() => deleteVaultEntry(entry.id)} className="text-slate-600 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100">
                                <Trash2 size={10} />
                              </button>
                            </div>
                            <div className="mt-2 flex items-center gap-2">
                              <div className="flex-1 bg-black/40 rounded px-2 py-1 flex items-center gap-2">
                                <p className="text-[10px] font-mono text-blue-300 truncate tracking-tight">{entry.password}</p>
                              </div>
                              <button 
                                onClick={() => copyToClipboard(entry.password, entry.id)}
                                className="px-2 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded text-[10px] font-bold transition-all shadow-md shadow-blue-600/20 active:scale-95"
                              >
                                {copiedId === entry.id ? t.vault.copied : t.vault.copy}
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Top Right Controls */}
      <div className="fixed top-4 right-4 md:top-6 md:right-6 flex items-center gap-2 md:gap-3 z-50">
        <button 
          onClick={() => setIsHelpOpen(true)}
          className="w-10 h-10 flex items-center justify-center rounded-full bg-slate-800/60 backdrop-blur-md border border-white/10 text-slate-400 hover:text-white transition-all shadow-lg"
          aria-label={t.ariaLabels.helpButton}
        >
          <HelpCircle size={18} />
        </button>

        <div className="flex bg-slate-800/60 backdrop-blur-md border border-white/10 p-1 rounded-full shadow-lg" role="group" aria-label="Language selection">
          <button 
            onClick={() => setLang('en')}
            className={`px-3 py-1 rounded-full text-[10px] font-bold transition-all ${lang === 'en' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-400 hover:text-white'}`}
          >
            EN
          </button>
          <button 
            onClick={() => setLang('es')}
            className={`px-3 py-1 rounded-full text-[10px] font-bold transition-all ${lang === 'es' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-400 hover:text-white'}`}
          >
            ES
          </button>
        </div>
      </div>

      <header className="w-full max-w-4xl flex flex-col items-center mb-12 animate-in fade-in slide-in-from-top duration-700">
        <div className="bg-blue-600 p-3 rounded-2xl mb-4 shadow-xl shadow-blue-500/30">
          <Shield size={36} className="text-white" />
        </div>
        <h1 className="text-4xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
          {t.title}
        </h1>
        <p className="text-slate-400 mt-2 text-center max-w-lg font-medium">
          {t.subtitle}
        </p>
      </header>

      <main className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 gap-8">
        <div className="lg:col-span-4 space-y-6">
          <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-6 backdrop-blur-sm shadow-sm">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2 text-slate-200">
              <Sliders className="text-blue-400" size={20} />
              {t.modeLabel}
            </h2>
            <div className="flex flex-col gap-3">
              <button
                onClick={() => {setMode(OperationMode.ENCRYPT); setTargetFiles([]); setSuccess(null); setError(null); setLegitimacyMeta(null);}}
                className={`flex items-center gap-4 p-4 rounded-xl border transition-all ${mode === OperationMode.ENCRYPT ? 'bg-blue-600 border-blue-500 text-white shadow-xl shadow-blue-500/20' : 'bg-slate-800 border-slate-700 hover:border-slate-600 text-slate-300'}`}
              >
                <Lock size={20} />
                <div className="text-left">
                  <p className="font-bold text-sm">{t.encryptMode}</p>
                  <p className="text-xs opacity-70">{t.encryptSub}</p>
                </div>
              </button>
              <button
                onClick={() => {setMode(OperationMode.DECRYPT); setTargetFiles([]); setSuccess(null); setError(null); setLegitimacyMeta(null);}}
                className={`flex items-center gap-4 p-4 rounded-xl border transition-all ${mode === OperationMode.DECRYPT ? 'bg-emerald-600 border-emerald-500 text-white shadow-xl shadow-emerald-500/20' : 'bg-slate-800 border-slate-700 hover:border-slate-600 text-slate-300'}`}
              >
                <Key size={20} />
                <div className="text-left">
                  <p className="font-bold text-sm">{t.decryptMode}</p>
                  <p className="text-xs opacity-70">{t.decryptSub}</p>
                </div>
              </button>
            </div>
          </div>

          <div className="bg-slate-800/30 border border-slate-700/50 rounded-2xl p-6">
            <h3 className="text-sm font-semibold text-slate-500 uppercase tracking-widest mb-4">{t.integrityTitle}</h3>
            {legitimacyMeta ? (
              <div className="space-y-4 animate-in fade-in duration-500">
                <div className="flex items-center gap-2 text-emerald-400 text-sm font-bold">
                  <CheckCircle size={16} />
                  <span>{t.authenticityConfirmed}</span>
                </div>
                <div className="bg-slate-900/50 rounded-lg p-3 space-y-2 border border-white/5 shadow-inner">
                  <p className="text-[10px] text-slate-500 uppercase font-bold">{t.originalName}</p>
                  <p className="text-xs font-mono text-slate-300 truncate">{legitimacyMeta.originalName}</p>
                  <p className="text-[10px] text-slate-500 uppercase mt-2 font-bold">{t.sealingTime}</p>
                  <p className="text-xs font-mono text-slate-300">{new Date(legitimacyMeta.timestamp).toLocaleString()}</p>
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-600 italic">{t.integrityPrompt}</p>
            )}
          </div>
        </div>

        <div className="lg:col-span-8 space-y-6">
          <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-6 md:p-8 backdrop-blur-sm shadow-xl transition-all">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mb-8">
              <FileSelector 
                label={mode === OperationMode.ENCRYPT ? t.step1Encrypt : t.step1Decrypt}
                icon={mode === OperationMode.ENCRYPT ? "ShieldCheck" : "PackageOpen"}
                onFilesSelect={setTargetFiles}
                selectedFiles={targetFiles}
                accept={targetAccept}
                description={mode === OperationMode.ENCRYPT ? t.step1DescEncrypt : t.step1DescDecrypt}
                accentColor={mode === OperationMode.ENCRYPT ? "blue" : "emerald"}
                allowMultiple={true}
                allowFolder={mode === OperationMode.ENCRYPT}
                translations={t.fileSelector}
                activeFileIndex={isLoading ? progress.current - 1 : undefined}
                activeFileProgress={isLoading ? progress.percent : undefined}
              />
              <div className="flex flex-col gap-2">
                <FileSelector 
                  label={t.step2Label}
                  icon="Fingerprint"
                  onFilesSelect={(files) => setKeyFile(files[0] || null)}
                  selectedFiles={keyFile ? [keyFile] : []}
                  description={t.step2Desc}
                  accentColor="amber"
                  translations={t.fileSelector}
                />
                {mode === OperationMode.ENCRYPT && (
                  <button onClick={handleGenerateKey} className="mt-2 py-2 px-4 rounded-xl border border-amber-500/30 bg-amber-500/5 text-amber-400 text-xs font-bold uppercase hover:bg-amber-500/10 transition-all shadow-sm flex items-center justify-center gap-2">
                    <Wand2 size={14} />
                    {t.btnGenerateKey}
                  </button>
                )}
              </div>
            </div>

            <div className="mb-8 space-y-6">
              {targetFiles.length === 1 && (
                <div className="space-y-2 animate-in fade-in slide-in-from-bottom duration-300">
                  <label htmlFor="output-name" className="text-sm font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                    <FileSignature className="text-blue-500" size={16} />
                    {t.outputNameLabel}
                  </label>
                  <input
                    id="output-name"
                    type="text"
                    value={customOutputName}
                    onChange={(e) => setCustomOutputName(e.target.value)}
                    placeholder={t.outputNamePlaceholder}
                    className="w-full bg-slate-900/50 border-2 border-slate-700 rounded-xl px-4 py-3 text-white placeholder:text-slate-600 focus:outline-none focus:border-blue-500/50 transition-all font-medium"
                  />
                </div>
              )}

              <div className="space-y-4">
                <div className="flex justify-between items-end">
                  <label className="text-sm font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                    <Key className="text-blue-500" size={16} />
                    {t.passwordLabel}
                  </label>
                  <div className="flex items-center gap-3">
                    {mode === OperationMode.ENCRYPT && (
                      <button onClick={handleGeneratePassword} className="text-[10px] font-bold uppercase text-blue-400 hover:text-blue-300 transition-colors flex items-center gap-1.5 px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20">
                        <Dices size={12} /> {t.btnGeneratePass}
                      </button>
                    )}
                    {password && <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded transition-all duration-300 ${passwordStrength.color} text-white`}>{passwordStrength.label}</span>}
                  </div>
                </div>
                
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={t.passwordPlaceholder}
                    className="w-full bg-slate-900/50 border border-slate-700 rounded-xl px-4 py-3 text-white placeholder:text-slate-600 focus:outline-none focus:border-blue-500/50 transition-all shadow-inner"
                  />
                  <button onClick={() => setShowPassword(!showPassword)} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors">
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>

                {password && (
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mt-3 animate-in fade-in slide-in-from-top-1 duration-300">
                    {Object.entries(passwordStrength.checks).map(([key, met]) => (
                      <div key={key} className={`flex items-center gap-2 text-[10px] font-bold uppercase transition-colors ${met ? 'text-emerald-400' : 'text-slate-600'}`}>
                        {met ? <Check size={10} /> : <Circle size={10} />}
                        <span>{(t.passCriteria as any)[key]}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {securityTip && (
              <div className="mb-8 p-4 bg-blue-500/10 border border-blue-500/20 rounded-xl flex gap-3 items-start animate-in fade-in duration-500 relative overflow-hidden">
                {strictPrivacy && (
                  <div className="absolute top-0 right-0 p-2 opacity-20">
                    <Shield size={40} className="text-emerald-500" />
                  </div>
                )}
                <ShieldAlert className={strictPrivacy ? "text-emerald-400 mt-1" : "text-blue-400 mt-1"} size={18} />
                <div className="flex flex-col gap-1">
                  <p className="text-xs text-blue-200/80 italic leading-relaxed">"{securityTip}"</p>
                  {strictPrivacy && (
                    <span className="text-[8px] uppercase font-black text-emerald-500/50 tracking-tighter">Offline Protection Active</span>
                  )}
                </div>
              </div>
            )}

            {error && (
              <div className="mb-6 p-4 rounded-xl text-sm flex items-start gap-3 border bg-red-500/10 border-red-500/20 text-red-400 animate-in shake duration-300">
                <AlertTriangle className="mt-0.5" size={18} />
                <p className="opacity-90">{error}</p>
              </div>
            )}

            {success && (
              <div className="mb-6 p-4 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl text-sm flex items-center justify-between gap-3 animate-in fade-in duration-300">
                <div className="flex items-center gap-3 font-bold">
                  <CheckCircle2 size={18} />
                  {success}
                </div>
                {mode === OperationMode.ENCRYPT && password && (
                  <button onClick={handleSaveToVault} className="text-[10px] uppercase font-black bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-1.5 rounded-lg transition-all shadow-lg active:scale-95 flex items-center gap-1">
                    <Save size={12} /> {t.vault.saveToVault}
                  </button>
                )}
              </div>
            )}

            <button
              disabled={isButtonDisabled}
              onClick={handleProcess}
              className={`w-full py-4 rounded-xl font-bold text-lg transition-all flex flex-col items-center justify-center gap-1 active:scale-[0.98] ${isButtonDisabled ? 'bg-slate-700 text-slate-500 cursor-not-allowed' : mode === OperationMode.ENCRYPT ? 'bg-blue-600 hover:bg-blue-500 text-white shadow-xl shadow-blue-600/30' : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-xl shadow-emerald-600/30'}`}
            >
              {isLoading ? (
                <div className="flex flex-col items-center gap-2">
                  <div className="flex items-center gap-3">
                    <Loader2 className="animate-spin" size={20} />
                    <span>{t.processing} {progress.current} {t.of} {progress.total}...</span>
                  </div>
                  <div className="w-48 h-1 bg-white/20 rounded-full overflow-hidden">
                    <div className="h-full bg-white transition-all duration-300" style={{ width: `${(progress.current / progress.total) * 100}%` }} />
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-3">
                  {mode === OperationMode.ENCRYPT ? <UserCheck size={24} /> : <Unlock size={24} />}
                  <span>{mode === OperationMode.ENCRYPT ? t.btnSeal : t.btnUnlock}</span>
                </div>
              )}
            </button>
          </div>
        </div>
      </main>

      <footer className="mt-auto pt-12 pb-6 text-slate-500 text-[10px] text-center uppercase tracking-widest opacity-60">
        <p>{t.footer}</p>
      </footer>
    </div>
  );
};

export default App;
